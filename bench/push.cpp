// Measure push throughput, latency and runtime state using an isolated transport fixture.
// Use probe.proto without adding benchmark fields to production SessionPacket.
#include "fixture.hpp"
#include "probe.grpc.pb.h"

#include <grpc/impl/channel_arg_names.h>
#include <grpcpp/grpcpp.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace astra;
using Time = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {
/// Validated workload dimensions and fixed resource ceilings for the independent push fixture.
struct ProbeConfig {
    /// Initial Registry entries: default 1000, range 1..100000; each has a 128-byte payload.
    /// Initial Catalog entries: default 1000, range 1..10000.
    /// Catalog payload bytes: default 256, range 64..1024.
    /// Subscriptions required before production: default 1, range 1..64.
    /// Aggregate source updates per second: default 2000, range 1..200000; do not multiply by subscribers.
    /// Hot keys: zero uses all keys; otherwise at most min(registries, catalogs).
    std::uint64_t registries = 1000, catalogs = 1000, bytes = 256, fanout = 1, rate = 2000, hot = 0;
    /// Production duration stored in seconds, default 3 s; --milliseconds accepts 200..30000 ms.
    double seconds = 3;
    /// Default scheduling is about 1 ms; burst batches about 50 ms of progress without changing the total target rate.
    /// fresh releases completed messages; reuse retains each slot's Protobuf object for the allocation comparison.
    bool burst = false, fresh = false;
    /// registry/catalog/mixed mode; mixed uses a 1:3 update ratio interleaved with snapshot fragments.
    /// TLS listen address, default 127.0.0.1:0; gRPC validates it when binding.
    std::string mode = "mixed", address = "127.0.0.1:0";
};

/// Own one queued wire event together with its monotonic enqueue time.
struct Queued {
    /// Own one encoded control or update event shared across queued readers.
    proto::astra::bench::v1::Event event;
    /// Record monotonic queue-entry time for bounded backlog expiry.
    Time::time_point created;
};

/// Correlate a source revision with its planned monotonic publication time.
struct Stamp {
    /// Identify the source revision currently occupying this reusable latency slot; zero is unused.
    std::uint64_t revision{};
    /// Keep the planned monotonic publication time so queueing contributes to measured latency.
    Time::time_point scheduled;
};
class Session;

/// Own the complete initial tables, a 512-entry shared broadcast ring and 16384 sparse latency slots, matching the Rust fixture's budgets.
struct Hub {
    /// Own the fixed workload, queue, and timing limits for this isolated push probe.
    ProbeConfig config;
    /// Serialize producer updates, session queue state, and progress accounting.
    std::mutex mutex;
    /// Wake the producer when the required sessions join or shutdown is requested.
    std::condition_variable ready;
    /// Borrow active reactors; their completion removes them under mutex before destruction.
    std::vector<Session*> sessions;
    /// Own the latest revision and payload per probe key for initial snapshots.
    std::unordered_map<std::string, std::pair<std::uint64_t, std::string>> values;
    /// Retain at most 512 shared broadcast events, indexed by sequence modulo capacity.
    std::array<std::shared_ptr<const Queued>, 512> ring{};
    /// Correlate progress with 16384 reusable revision timestamps; overwritten slots count as expired samples.
    std::array<Stamp, 16384> stamps{};
    /// Count emitted events and applied source revisions separately, both starting at zero.
    std::uint64_t sequence = 0, revision = 0;
    /// Count sessions admitted to the current probe before the common production start.
    std::size_t joined = 0;
    /// Track production completion and requested shutdown separately; neither initially holds.
    bool finished = false, stop = false;
    /// Own the bounded publication worker and join it during hub teardown.
    std::jthread producer;

    explicit Hub(ProbeConfig input) : config(std::move(input)) {
        values.reserve(config.registries + config.catalogs);
        for (const auto domain : {proto::astra::bench::v1::DOMAIN_REGISTRY, proto::astra::bench::v1::DOMAIN_CATALOG}) {
            const auto count = domain == proto::astra::bench::v1::DOMAIN_REGISTRY ? config.registries : config.catalogs;
            const auto size = domain == proto::astra::bench::v1::DOMAIN_REGISTRY ? 128 : config.bytes;
            for (std::uint64_t i = 0; i < count; ++i) {
                auto data = std::string(size, '1');
                for (unsigned byte = 0; byte < 8; ++byte) {
                    data[byte] = static_cast<char>((i >> (byte * 8)) & 255);
                }
                values.emplace(key(domain, i, false), std::pair{0, std::move(data)});
            }
        }
    }

    std::string key(proto::astra::bench::v1::Domain domain, std::uint64_t index, bool update = true) const {
        const auto count = domain == proto::astra::bench::v1::DOMAIN_REGISTRY ? config.registries : config.catalogs;
        index %= update && config.hot ? config.hot : count;
        auto number = std::to_string(index);
        number.insert(0, 6 - number.size(), '0');
        return (domain == proto::astra::bench::v1::DOMAIN_REGISTRY ? "registry/service/instance/" : "catalog/config/") + number;
    }

    void publish(proto::astra::bench::v1::Event event);
    bool apply(proto::astra::bench::v1::Domain domain, std::string data, Time::time_point scheduled);
    void produce();
    void shutdown();
};

/// gRPC owns Reactor termination; OnDone unlinks it under the Hub lock before release. Publishers access raw pointers only under that lock.
class Session final : public grpc::ServerBidiReactor<proto::astra::bench::v1::Control, proto::astra::bench::v1::Event> {
public:
    Session(Hub& hub, grpc::CallbackServerContext* context) : hub_(hub), context_(context), latency_(100001) {
        hub_.sessions.push_back(this);
        StartSendInitialMetadata();
        read();
    }

    void OnSendInitialMetadataDone(bool ok) override {
        guarded([&] {
            metadata_ = true;
            if (!ok) {
                fail("response metadata failed");
            }
            pump();
        });
    }

    void OnReadDone(bool ok) override {
        guarded([&] {
            reading_ = false;
            if (!ok) {
                fail("control stream closed");
                return;
            }
            // Control broadcasts may pump this session; retain exclusive receive-message ownership until Clear before issuing another read.
            processingRead_ = true;
            control();
            input_.Clear();
            processingRead_ = false;
            read();
            pump();
        });
    }

    void OnWriteDone(bool ok) override {
        guarded([&] {
            writing_ = false;
            const bool completed = output_[head_]->has_completed();
            if (hub_.config.fresh) {
                output_[head_].reset();
            }
            head_ = (head_ + 1) % output_.size();
            --queued_;
            if (!ok) {
                fail("event write failed");
            }
            if (completed && ok) {
                closing_ = true;
            }
            pump();
            read();
        });
    }

    void OnCancel() override {
        guarded([&] { fail("session cancelled"); });
    }

    void OnDone() override {
        {
            std::lock_guard lock(hub_.mutex);
            std::erase(hub_.sessions, this);
        }
        delete this;
    }

    /// One in-flight write plus 16 queued messages; fresh creates each message while reuse retains each slot's ordinary Protobuf object.
    void pump() {
        if (finishing_) {
            return;
        }
        if (closing_) {
            if (!writing_ && metadata_) {
                finishing_ = true;
                Finish(status_);
            }
            return;
        }
        while (queued_ < output_.size()) {
            std::shared_ptr<const Queued> next;
            if (!controls_.empty()) {
                next = std::move(controls_.front());
                controls_.pop_front();
            } else if (joined_ && cursor_ <= hub_.sequence) {
                if (hub_.sequence - cursor_ >= hub_.ring.size()) {
                    fail("receiver lagged; resynchronization required");
                    return;
                }
                next = hub_.ring[cursor_++ % hub_.ring.size()];
            } else {
                break;
            }
            auto& slot = output_[(head_ + queued_) % output_.size()];
            if (!slot) {
                slot = std::make_unique<proto::astra::bench::v1::Event>();
            }
            slot->CopyFrom(next->event);
            slot->set_queue_micros(static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Time::now() - next->created).count()));
            if (slot->has_drained()) {
                drained_ = slot->drained();
            }
            ++queued_;
        }
        if (queued_ && !writing_ && metadata_) {
            writing_ = true;
            // Coalesce at most 16 ready updates; flush the final update and control replies immediately without waiting for future traffic.
            grpc::WriteOptions options;
            if (queued_ > 1 && output_[head_]->has_update() && bufferedWrites_ < 15) {
                options.set_buffer_hint();
                ++bufferedWrites_;
            } else {
                bufferedWrites_ = 0;
            }
            StartWrite(output_[head_].get(), options);
        }
        read();
    }

    void fail(std::string_view reason) {
        if (!closing_) {
            closing_ = true;
            std::cerr << "push session ended: " << reason << '\n';
            status_ = grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, std::string(reason));
            context_->TryCancel();
        }
        pump();
    }

private:
    /// Exceptions cannot cross gRPC callbacks; cancellation drives OnCancel/OnDone, which own final release.
    template <class Action>
    void guarded(Action action) noexcept {
        try {
            std::lock_guard lock(hub_.mutex);
            action();
        } catch (...) {
            context_->TryCancel();
        }
    }

    void read() {
        if (!reading_ && !processingRead_ && !closing_ && controls_.size() < 8) {
            reading_ = true;
            StartRead(&input_);
        }
    }

    std::uint64_t percentile(double fraction) const {
        const auto target = static_cast<std::uint64_t>(std::ceil(static_cast<double>(samples_) * fraction));
        if (!target) {
            return 0;
        }
        std::uint64_t count = 0;
        for (std::size_t i = 0; i < latency_.size(); ++i) {
            count += latency_[i];
            if (count >= target) {
                return (i + 1) * 100;
            }
        }
        return 10000100;
    }

    void control() {
        if (!joined_) {
            if (!input_.has_join() || !input_.join() || hub_.joined >= hub_.config.fanout) {
                fail("join required or recipient limit");
                return;
            }
            joined_ = true;
            cursor_ = hub_.sequence + 1;
            if (++hub_.joined == hub_.config.fanout) {
                hub_.ready.notify_one();
            }
            return;
        }
        proto::astra::bench::v1::Event reply;
        switch (input_.command_case()) {
        case proto::astra::bench::v1::Control::kPing:
            reply.set_pong(input_.ping());
            break;
        case proto::astra::bench::v1::Control::kPublish:
            if (!input_.publish().request() || input_.publish().data().size() > 1024) {
                fail("invalid publish");
                return;
            }
            if (hub_.apply(proto::astra::bench::v1::DOMAIN_CATALOG, input_.publish().data(), Time::now())) {
                reply.set_accepted(input_.publish().request());
            } else {
                reply.set_rejected(input_.publish().request());
            }
            break;
        case proto::astra::bench::v1::Control::kProgress: {
            const auto& progress = input_.progress();
            if (progress.final()) {
                if (!drained_ || *drained_ != progress.revision()) {
                    fail("invalid final progress");
                    return;
                }
                auto* result = reply.mutable_completed();
                result->set_revision(progress.revision());
                result->set_sampled_updates(samples_);
                result->set_expired_samples(expired_);
                result->set_update_p50_micros(percentile(0.50));
                result->set_update_p95_micros(percentile(0.95));
                result->set_update_p99_micros(percentile(0.99));
            } else {
                if (progress.revision() <= lastProgress_ || progress.revision() > hub_.revision) {
                    fail("invalid progress revision");
                    return;
                }
                lastProgress_ = progress.revision();
                const auto stamp = hub_.stamps[progress.revision() % hub_.stamps.size()];
                if (stamp.revision != progress.revision()) {
                    ++expired_;
                } else {
                    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(Time::now() - stamp.scheduled).count();
                    ++latency_[static_cast<std::size_t>(std::clamp<std::int64_t>(micros / 100, 0, 100000))];
                    ++samples_;
                }
                return;
            }
            break;
        }
        default:
            fail("invalid control");
            return;
        }
        controls_.push_back(std::make_shared<Queued>(Queued{std::move(reply), Time::now()}));
    }

    /// Borrow the shared hub until this reactor completes and leaves its session index.
    Hub& hub_;
    /// Borrow gRPC callback context for cancellation and completion of this RPC only.
    grpc::CallbackServerContext* context_;
    /// Own the control-message buffer while an asynchronous read is outstanding.
    proto::astra::bench::v1::Control input_;
    /// Keep seventeen write buffers stable until gRPC releases each submitted event.
    std::array<std::unique_ptr<proto::astra::bench::v1::Event>, 17> output_;
    /// Retain control replies separately from the shared update ring until queued for writing.
    std::deque<std::shared_ptr<const Queued>> controls_;
    /// Count latency samples in 100-microsecond buckets, clamping the final overflow bucket.
    std::vector<std::uint64_t> latency_;
    /// Track ring cursor, acknowledged revision, measured sample count, and overwritten-sample count.
    std::uint64_t cursor_ = 0, lastProgress_ = 0, samples_ = 0, expired_ = 0;
    /// Remember the final drained revision expected in the completion acknowledgment; absent before drainage.
    std::optional<std::uint64_t> drained_;
    /// Track the output-ring head, occupied slots, and buffered writes awaiting a flush.
    std::size_t head_ = 0, queued_ = 0, bufferedWrites_ = 0;
    /// Track join, read, read-processing, write, metadata, close, and Finish ownership across gRPC callbacks.
    bool joined_ = false, reading_ = false, processingRead_ = false, writing_ = false, metadata_ = false, closing_ = false, finishing_ = false;
    /// Retain the terminal RPC status until the single Finish transition.
    grpc::Status status_;
};

void Hub::publish(proto::astra::bench::v1::Event event) {
    ring[++sequence % ring.size()] = std::make_shared<Queued>(Queued{std::move(event), Time::now()});
    for (auto* session : sessions) {
        session->pump();
    }
}

bool Hub::apply(proto::astra::bench::v1::Domain domain, std::string data, Time::time_point scheduled) {
    if (finished) {
        return false;
    }
    auto name = key(domain, ++revision);
    values.at(name) = {revision, data};
    stamps[revision % stamps.size()] = Stamp{revision, scheduled};
    proto::astra::bench::v1::Event message;
    auto* update = message.mutable_update();
    update->set_revision(revision);
    update->set_key(std::move(name));
    update->set_data(std::move(data));
    update->set_domain(domain);
    publish(std::move(message));
    return true;
}

void Hub::produce() {
    try {
        std::unique_lock lock(mutex);
        if (!ready.wait_for(lock, 8s, [&] { return joined == config.fanout || stop; }) || stop) {
            return;
        }
        proto::astra::bench::v1::Event first;
        first.set_ready(true);
        publish(std::move(first));
        const auto start = Time::now();
        const auto target = static_cast<std::uint64_t>(static_cast<double>(config.rate) * config.seconds);
        std::uint64_t count = 0, snapshots = 0;
        auto tick = start;
        while (count < target && !stop) {
            lock.unlock();
            std::this_thread::sleep_until(tick);
            lock.lock();
            tick = Time::now() + (config.burst ? 50ms : 1ms);
            const auto due =
                std::min(target, static_cast<std::uint64_t>(std::chrono::duration<double>(Time::now() - start).count() * static_cast<double>(config.rate)));
            while (count < due && !stop) {
                const auto domain = config.mode == "registry" || (config.mode == "mixed" && count % 4 == 0) ? proto::astra::bench::v1::DOMAIN_REGISTRY
                                                                                                            : proto::astra::bench::v1::DOMAIN_CATALOG;
                auto data = std::string(domain == proto::astra::bench::v1::DOMAIN_REGISTRY ? 128 : config.bytes, 'Z');
                for (unsigned byte = 0; byte < 8; ++byte) {
                    data[byte] = static_cast<char>((count >> (byte * 8)) & 255);
                }
                const auto scheduled = start + std::chrono::duration_cast<Time::duration>(
                                                   std::chrono::duration<double>(static_cast<double>(count + 1) / static_cast<double>(config.rate)));
                apply(domain, std::move(data), scheduled);
                if (++count % 64 == 0) {
                    lock.unlock();
                    std::this_thread::yield();
                    lock.lock();
                }
            }
            if (config.mode == "mixed" &&
                static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Time::now() - start).count()) / 500 > snapshots) {
                ++snapshots;
                for (int i = 0; i < 4; ++i) {
                    proto::astra::bench::v1::Event piece;
                    piece.set_snapshot(std::string(16384, '<'));
                    publish(std::move(piece));
                }
            }
        }
        finished = true;
        proto::astra::bench::v1::Event drained;
        drained.set_drained(revision);
        publish(std::move(drained));
    } catch (const std::exception& error) {
        std::cerr << "Producer failed: " << error.what() << '\n';
        shutdown();
    }
}

void Hub::shutdown() {
    std::lock_guard lock(mutex);
    stop = true;
    ready.notify_one();
    for (auto* session : sessions) {
        session->fail("server stopping");
    }
}

class Service final : public proto::astra::bench::v1::TransportProbe::CallbackService {
public:
    Service(Hub& hub, std::shared_ptr<Identity> identity) : hub_(hub), identity_(std::move(identity)) {
        proto::orbit::v1::Member member;
        member.set_galaxy("alpha");
        member.set_id("probe/" + std::to_string(hub_.config.fanout));
        const auto digest = identity_->principal("alpha", "127.0.0.1:39001");
        member.set_principal(digest.bytes.data(), digest.bytes.size());
        member.set_advertise("127.0.0.1:39001");
        member.set_epoch(1);
        member.set_role(proto::orbit::v1::ROLE_STAR);
        member.set_group("default");
        proto::astra::v1::Hello hello;
        hello.set_protocol_major(protocolMajor);
        hello.set_max_frame_bytes(32768);
        hello.set_admission(member.SerializeAsString());
        hello.set_admission_signature(test::sign(hello.admission()));
        proof_ = hello.SerializeAsString();
    }

    grpc::ServerBidiReactor<proto::astra::bench::v1::Control, proto::astra::bench::v1::Event>* Synchronize(grpc::CallbackServerContext* context) override {
        const auto entry = context->client_metadata().find("hello-bin");
        proto::astra::v1::Hello hello;
        if (entry == context->client_metadata().end() || entry->second.size() > 2048 ||
            !hello.ParseFromArray(entry->second.data(), static_cast<int>(entry->second.size())) || hello.protocol_major() != protocolMajor ||
            hello.max_frame_bytes() != 32768 ||
            !identity_
                 ->verify(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(hello.admission().data()), hello.admission().size()),
                          std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(hello.admission_signature().data()),
                                                        hello.admission_signature().size()))
                 .has_value()) {
            auto* rejected = new Rejected;
            rejected->Finish(grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "invalid test bearer"));
            return rejected;
        }
        context->AddInitialMetadata("hello-bin", proof_);
        std::lock_guard lock(hub_.mutex);
        return new Session(hub_, context);
    }

private:
    /// Finish an unaccepted stream and reclaim its reactor only after gRPC releases it.
    struct Rejected : grpc::ServerBidiReactor<proto::astra::bench::v1::Control, proto::astra::bench::v1::Event> {
        void OnDone() override {
            delete this;
        }
    };

    /// Borrow the probe hub for every accepted session; the service does not own its worker.
    Hub& hub_;
    /// Retain the public fixture identity used to authenticate probe sessions.
    std::shared_ptr<Identity> identity_;
    /// Own the signed admission proof sent with the isolated probe handshake.
    std::string proof_;
};

std::atomic_bool interrupted{};
static_assert(std::atomic_bool::is_always_lock_free);

void interrupt(int) {
    interrupted.store(true, std::memory_order_relaxed);
}
} // namespace

int main(int argc, char** argv) {
    try {
        ProbeConfig config;
        std::map<std::string, std::string> options;
        for (int i = 1; i < argc; ++i) {
            std::string argument(argv[i]);
            const auto separator = argument.find('=');
            if (separator == std::string::npos || !options.emplace(argument.substr(0, separator), argument.substr(separator + 1)).second) {
                throw std::runtime_error("Expected unique --name=value");
            }
        }
        auto take = [&](const char* name, std::string fallback) {
            auto item = options.extract(name);
            return item.empty() ? fallback : std::move(item.mapped());
        };
        auto number = [&](const char* name, std::uint64_t fallback) {
            auto text = take(name, std::to_string(fallback));
            std::uint64_t value = 0;
            auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (error != std::errc{} || end != text.data() + text.size()) {
                throw std::runtime_error("Invalid numeric probe option");
            }
            return value;
        };
        config.address = take("--address", config.address);
        config.mode = take("--data-mode", config.mode);
        config.registries = number("--registries", 1000);
        config.catalogs = number("--catalogs", 1000);
        config.bytes = number("--catalog-bytes", 256);
        config.fanout = number("--fanout", 1);
        config.rate = number("--rate", 2000);
        config.hot = number("--hot-keys", 0);
        config.seconds = static_cast<double>(number("--milliseconds", 3000)) / 1000.0;
        config.burst = number("--burst", 0) != 0;
        config.fresh = number("--fresh", 0) != 0;
        if (!options.empty() || !config.registries || config.registries > 100000 || !config.catalogs || config.catalogs > 10000 || config.bytes < 64 ||
            config.bytes > 1024 || !config.fanout || config.fanout > 64 || !config.rate || config.rate > 200000 ||
            config.hot > std::min(config.registries, config.catalogs) || config.seconds < 0.2 || config.seconds > 30 ||
            (config.mode != "mixed" && config.mode != "registry" && config.mode != "catalog")) {
            throw std::runtime_error("Invalid probe limits");
        }
        auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", Endpoint::parse("127.0.0.1:39001").value()).value();
        Hub hub(config);
        Service service(hub, identity);
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(32768);
        builder.SetMaxSendMessageSize(32768);
        builder.AddChannelArgument("grpc.http2.bdp_probe", 0);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_STREAM_LOOKAHEAD_BYTES, 65535);
        builder.AddChannelArgument("grpc.max_concurrent_streams", 1);
        builder.AddChannelArgument("grpc.server_handshake_timeout_ms", 5000);
        builder.RegisterService(&service);
        int port = 0;
        builder.AddListeningPort(config.address, identity->serverCredentials(), &port);
        auto server = builder.BuildAndStart();
        if (!server || !port) {
            throw std::runtime_error("Cannot start C++ push fixture");
        }
        std::signal(SIGTERM, interrupt);
        std::signal(SIGINT, interrupt);
        std::signal(SIGPIPE, SIG_IGN);
        hub.producer = std::jthread([&] { hub.produce(); });
        std::cout << "{\"ready\":true,\"address\":\"127.0.0.1:" << port << "\"}\n"
                  << std::flush;
        const auto deadline = Time::now() + 60s;
        while (!interrupted.load(std::memory_order_relaxed) && Time::now() < deadline) {
            std::this_thread::sleep_for(20ms);
        }
        hub.shutdown();
        hub.producer.join();
        server->Shutdown(std::chrono::system_clock::now() + 5s);
        server->Wait();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Push fixture failed: " << error.what() << '\n';
        return 1;
    }
}
