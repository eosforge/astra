// Verify SDK Catalog state preservation under injected allocation failures.
#include "catalog_service.hpp"
#include "check.hpp"
#include "identity.hpp"
#include <comet/client.hpp>

#include <grpcpp/server_builder.h>

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <limits>
#include <source_location>
#include <thread>

namespace {
using namespace std::chrono_literals;

/// Faults follow actual native commits; one stalled Watch leaves subsequent production streaming intact.
class Faults final : public proto::comet::v1::Catalog::CallbackService {
public:
    /// Actual version Query count, excluding Watch.
    std::atomic_uint queries{};
    /// Remaining injections where another writer raises the batch versions before Publish.
    std::atomic_uint conflicts{};
    /// Next Query omits entries and must be rejected before commit.
    std::atomic_bool malformed{};
    /// Next Publish commits but loses its receipt.
    std::atomic_bool lost{};
    /// 0 normal; 1 stalled first frame; 2 stalled partial batch; 3 partial-batch EOF; 4 EOF before first frame.
    std::atomic_int stalled{};
    /// Actual received Publish count, not business version.
    std::atomic_uint writes{};
    /// Actual Watch count verifies recovery starts after the old stream stops.
    std::atomic_uint watches{};
    /// Actual admission and native commits must succeed on injected paths.
    std::atomic_bool valid{true};
    /// Fixed available business time; SDK timeouts still use actual monotonic time.
    astra::Catalog::State state;
    /// All normal RPCs use the production service.
    astra::Catalog::Service service;

    /// Gateway outlives this fixture; state outlives service.
    explicit Faults(astra::Gateway& gateway) : state([] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true}); }, {}), service(state, gateway), gateway_(gateway) {}

    /// Query reads actual service watermarks; invalid replies exercise SDK correspondence checks only.
    grpc::ServerUnaryReactor* Query(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogQueryRequest* request, proto::comet::v1::CatalogQueryReply* reply) override {
        ++queries;
        if (!malformed.exchange(false)) {
            return service.Query(context, request, reply);
        }
        reply->set_instance("catalog-fault"); // Deliberately omit every Key; Publish must not be sent.
        auto* reactor = context->DefaultReactor();
        reactor->Finish(grpc::Status::OK);
        return reactor;
    }

    grpc::ServerUnaryReactor* Publish(grpc::CallbackServerContext* context, const proto::comet::v1::PublishRequest* request, proto::comet::v1::PublishReply* reply) override {

        ++writes;
        if (conflicts.load() > 0) {
            --conflicts;
            std::vector<astra::Catalog::State::Entry> entries; // Inject an explicit version race between Query and Publish.
            for (const auto& entry : request->entries()) {
                entries.push_back({entry.key(), std::make_shared<const astra::Catalog::Buffer>(1, 42)});
            }
            if (!state.publish({request->scope().sector(), request->scope().spectrum()}, entries, request->version() + 10, request->ttl_ms())) {
                valid.store(false);
            }
        }
        if (!lost.exchange(false)) {
            return service.Publish(context, request, reply);
        }
        auto permit = gateway_.enter(*context);                   // Preserve actual login and readiness checks.
        std::expected<void, astra::Catalog::State::Error> result; // Inject after production native commit without bypassing batch boundaries.
        if (request->entries().empty()) {
            auto body = std::make_shared<const astra::Catalog::Buffer>(request->value().begin(), request->value().end());
            result = state.publish({request->scope().sector(), request->scope().spectrum()}, request->key(), std::move(body), request->version(), request->ttl_ms());
        } else {
            std::vector<astra::Catalog::State::Entry> entries; // Commit the whole batch once, then lose its entire receipt.
            for (const auto& entry : request->entries()) {
                entries.push_back({entry.key(), std::make_shared<const astra::Catalog::Buffer>(entry.value().begin(), entry.value().end())});
            }
            result = state.publish({request->scope().sector(), request->scope().spectrum()}, entries, request->version(), request->ttl_ms());
        }
        if (!permit || !result) {
            valid.store(false);
        }
        auto* reactor = context->DefaultReactor(); // gRPC owns the default reactor; uncertain failure carries no unapplied detail.
        reactor->Finish(grpc::Status(grpc::StatusCode::DEADLINE_EXCEEDED, "Injected confirmation loss"));
        return reactor;
    }

    /// Normal frequent Renew still enforces actual deadline and source rules.
    grpc::ServerUnaryReactor* Renew(grpc::CallbackServerContext* context, const proto::comet::v1::CatalogRenewRequest* request, proto::comet::v1::Empty* reply) override {
        return service.Renew(context, request, reply);
    }

    grpc::ServerWriteReactor<proto::comet::v1::CatalogWatchReply>* Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) override {
        ++watches;
        const auto mode = stalled.exchange(0); // Inject once; later recovery uses the full production pipeline.
        return mode == 0 ? service.Watch(context, request) : new Frozen(mode);
    }

private:
    /// After cancellation, finish only once the sole in-flight Write completes; OnDone alone releases the reactor.
    class Frozen final : public grpc::ServerWriteReactor<proto::comet::v1::CatalogWatchReply> {
    public:
        /// mode selects the four faults above; partial batches never become visible, and EOF must drain before Watch reopens.
        explicit Frozen(int mode) : writing_(mode == 2 || mode == 3), cancelled_(mode >= 3) {
            if (writing_) {
                page_.set_mode(proto::comet::v1::MODE_RESET);
                // Instance and complete cursor belong only on the final page; this simulates a valid partial stall without a separate protocol fault.
                auto* change = page_.add_changes(); // Page lifetime extends through OnDone.
                change->set_key("partial");
                change->set_value("not-installed");
                change->set_version(1);
                StartWrite(&page_);
            } else {
                finish(); // mode 4 emits EOF without an in-flight Write; mode 1 stalls before the first frame.
            }
        }

        /// Cancellation and Write callbacks may race; one short lock enforces a single Finish.
        void OnCancel() override {
            const std::lock_guard lock(mutex_);
            cancelled_ = true;
            finish();
        }

        /// Failed Write also enters termination without awaiting another application event.
        void OnWriteDone(bool ok) override {
            const std::lock_guard lock(mutex_);
            writing_ = false;
            cancelled_ = cancelled_ || !ok;
            finish();
        }

        /// No external owners; delete after final gRPC completion.
        void OnDone() override {
            delete this;
        }

    private:
        /// mutex_ is held; finish only without an in-flight Write, without blocking gRPC threads.
        void finish() {
            if (cancelled_ && !writing_ && !finished_) {
                finished_ = true;
                Finish(grpc::Status(grpc::StatusCode::CANCELLED, "Fixture stopped"));
            }
        }

        /// Partial batch encoded once; complete defaults to false.
        proto::comet::v1::CatalogWatchReply page_;
        /// Coordinates cancellation and write completion only.
        std::mutex mutex_;
        /// Whether the sole Write remains in flight.
        bool writing_{};
        /// Whether termination is required.
        bool cancelled_{};
        /// Ensures exactly one Finish.
        bool finished_{};
    };

    /// Uses the actual fixed Gateway without a separate authentication model.
    astra::Gateway& gateway_;
};

/// Own the public gateway, controlled Catalog service, and client for one isolated fault scenario.
class Fixture {
public:
    /// Production access table; this isolated test explicitly permits public access without login.
    astra::Access access;
    /// Bind the fixture access index to a local plaintext gateway for fault-injection requests.
    astra::Gateway gateway{access, "catalog-fault", false};
    /// Actual Catalog commit with controllable receipts.
    Faults faults{gateway};
    /// Cleanup awaits all reactors.
    comet::Client client;

    Fixture() {

        auto credentials = astra::Identity::external(std::filesystem::path(ASTRA_FIXTURES) / "star-a");
        CHECK(credentials);
        grpc::ServerBuilder builder;
        int port{}; // Independent loopback port per fixture, without shared deployment state.
        builder.AddListeningPort("127.0.0.1:0", *credentials, &port);
        builder.RegisterService(&gateway);
        builder.RegisterService(&faults);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        try {
            worker_ = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    faults.service.pump(std::chrono::steady_clock::now());
                    std::unique_lock lock(mutex_);
                    changed_.wait_for(lock, stop, 2ms, [] { return false; });
                }
            });
            gateway.ready();
            comet::Client::Options options;
            options.auth = false;
            options.endpoints = {"127.0.0.1:" + std::to_string(port)};
            options.ca = std::filesystem::path(ASTRA_FIXTURES) / "star-a" / "ca.pem";
            options.timeout = 500ms;
            auto opened = comet::Client::open(std::move(options));
            CHECK(opened);
            client = std::move(*opened);
        } catch (...) {
            stop();
            throw;
        }
    }

    /// Every success and failure path closes all fixture-owned resources.
    ~Fixture() {
        stop();
    }

private:
    /// Close SDK while server threads can drain Watch, then stop server and control loop.
    void stop() {
        client.close();
        if (!client.wait(5s)) {
            std::terminate();
        }
        gateway.stop();
        faults.service.stop();
        server_->Shutdown(std::chrono::system_clock::now() + 2s);
        server_->Wait();
        if (worker_.joinable()) {
            worker_.request_stop();
            changed_.notify_all();
            worker_.join();
        }
        faults.service.pump(std::chrono::steady_clock::now(), 65536);
    }

    /// Independent control-loop wake and stop lock.
    std::mutex mutex_;
    /// stop_token interrupts waits immediately.
    std::condition_variable_any changed_;
    /// Destroy after callbacks fully drain.
    std::unique_ptr<grpc::Server> server_;
    /// One service control thread per fixture, not per Publisher.
    std::jthread worker_;
};

/// condition is observable state and location preserves the caller; wait at most five seconds without treating long sleeps as evidence.
void eventually(auto&& condition, std::source_location location = std::source_location::current()) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!condition()) {
        astra::test::check(std::chrono::steady_clock::now() < deadline, "Expected asynchronous state was not reached", location);
        std::this_thread::sleep_for(1ms);
    }
}

/// Lost confirmation reports unknown without background replay after the old renewal period; a new object Queries its version baseline.
void lost() {

    Fixture fixture;
    fixture.faults.lost.store(true);
    auto publisher = fixture.client.publisher({"source", "main"});
    CHECK(publisher);
    const auto result = publisher->update("key", {7}, 1s);
    CHECK(!result && result.error().effect == comet::Error::Effect::Unknown);
    std::this_thread::sleep_for(500ms); // Bounded negative observation window catches the former TTL/3 automatic recovery.
    CHECK(fixture.faults.writes.load() == 1 && fixture.faults.queries.load() == 1 && fixture.faults.valid.load());
    CHECK(fixture.faults.state.find({"source", "main"}, "key")->record->version == 1);
    auto restarted = fixture.client.publisher({"source", "main"});
    CHECK(restarted);
    const auto next = restarted->update("key", {8}, 1s);
    CHECK(next && next->version == 2);
}

/// Synchronous batches install atomically across streamed pages; retained old views survive later commits.
void batches() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"batch", "main"});
    auto subscriber = fixture.client.subscriber({"batch", "main"});
    CHECK(publisher && subscriber);
    eventually([&] { return subscriber->watch().state() == comet::Subscriber::State::Ready; });
    const auto initial = subscriber->watch();                                           // Later batches must not mutate the old baseline.
    const auto body = std::make_shared<const std::vector<std::uint8_t>>(300 * 1024, 7); // 600 KiB total forces pagination.
    const auto result = publisher->update({{"a", body}, {"b", body}}, 1s);
    CHECK(result && result->version == 1);
    eventually([&] { const auto view = subscriber->watch(); CHECK(view.size() == 0 || view.size() == 2); return view.size() == 2; });
    CHECK(initial.size() == 0 && fixture.faults.valid.load());
    const auto frozen = subscriber->watch();
    const auto next = publisher->update({{"b", body}, {"a", body}}, 2s); // Explicit TTL on each call; a complete batch may reorder entries.
    CHECK(next && next->version == 2);
    eventually([&] { const auto view = subscriber->watch(); CHECK(view.find("a")->version == view.find("b")->version); return view.find("a")->version == 2; });
    CHECK(frozen.find("a")->version == 1 && frozen.find("b")->version == 1);
    const auto position = fixture.faults.state.source().position();
    std::this_thread::sleep_for(800ms); // Beyond the former two-second lease renewal period, source Renew must not increase.
    CHECK(fixture.faults.state.source().position() == position);
}

/// Only a version conflict proving the whole batch unapplied permits one repair; a second conflict returns immediately.
void conflicts() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"repair", "main"});
    CHECK(publisher);
    fixture.faults.conflicts.store(1);
    const auto repaired = publisher->update("key", {7}, 1s);
    CHECK(repaired && repaired->version == 12 && fixture.faults.writes.load() == 2 && fixture.faults.queries.load() == 2);
    fixture.faults.conflicts.store(2);
    const auto rejected = publisher->update("key", {8}, 1s);
    CHECK(!rejected && rejected.error().code == comet::Error::Code::Version && rejected.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.faults.writes.load() == 4 && fixture.faults.queries.load() == 3 && fixture.faults.valid.load());
}

/// Reject incomplete version replies and version exhaustion before sending, without implicit overwrite through overflow or missing entries.
void queries() {

    Fixture fixture;
    auto publisher = fixture.client.publisher({"query", "main"});
    CHECK(publisher);
    fixture.faults.malformed.store(true);
    const auto malformed = publisher->update("key", {7}, 1s);
    CHECK(!malformed && malformed.error().code == comet::Error::Code::Protocol && malformed.error().effect == comet::Error::Effect::Unapplied);
    CHECK(fixture.faults.writes.load() == 0);
    CHECK(fixture.faults.state.publish({"query", "main"}, "key", std::make_shared<const astra::Catalog::Buffer>(1, 7), std::numeric_limits<std::uint64_t>::max(), 1000));
    const auto exhausted = publisher->update("key", {8}, 1s);
    CHECK(!exhausted && exhausted.error().code == comet::Error::Code::Limit && fixture.faults.writes.load() == 0);
}

void stalled() {
    // Covers reading timeout, reads after consumed, hold return on first-frame or partial EOF, and reconnect.
    for (const int mode : {1, 2, 3, 4}) {
        Fixture fixture;
        fixture.faults.stalled.store(mode);
        auto subscriber = fixture.client.subscriber({"source", "main"});
        CHECK(subscriber);
        eventually([&] { const auto view = subscriber->watch(); CHECK(!view.find("partial")); CHECK(view.state() != comet::Subscriber::State::Failed); return fixture.faults.watches.load() >= 2 && view.state() == comet::Subscriber::State::Ready; });
        CHECK(subscriber->watch().size() == 0); // Recover the actual empty baseline without partial-batch contamination.
        subscriber->close();
        CHECK(subscriber->wait(3s));
    }
}

/// Close while awaiting first or next page without waiting for the no-progress deadline; the old stream must not recover after closure.
void cancelled() {
    for (const int mode : {1, 2}) {
        Fixture fixture; // Each round owns its port and Client, isolated from other fault cases.
        fixture.faults.stalled.store(mode);
        auto subscriber = fixture.client.subscriber({"source", "main"}); // First request entered the stalled fixture.
        CHECK(subscriber);
        eventually([&] { return fixture.faults.watches.load() != 0; });
        subscriber->close();
        CHECK(subscriber->wait(3s));
        CHECK(subscriber->watch().state() == comet::Subscriber::State::Closed && subscriber->watch().size() == 0);
        CHECK(fixture.client.exceptions() == 0); // wait confirms actual stream completion; do not assume scheduling prevents a timeout reconnect before closure.
    }
}
} // namespace

/// Runs real TLS batch, conflict, receipt-loss, stall, and cancellation cases.
int main() {
    try {
        batches();
        conflicts();
        queries();
        lost();
        stalled();
        cancelled();
        std::cout << "Catalog confirmation and Watch stall cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
