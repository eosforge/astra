// Measure public Comet operations against explicitly supplied live Star endpoints.
#include "delivery.hpp"
#include "measure.hpp"
#include <comet/client.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <mutex>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;

/// Bound waits for observable conditions; timeout fails the scenario without retrying uncertain writes.
void until(auto&& ready, std::chrono::seconds timeout = 30s) {
    const auto deadline = Measure::Clock::now() + timeout;
    while (!ready()) {
        Measure::require(Measure::Clock::now() < deadline);
        std::this_thread::sleep_for(50us);
    }
}

/// Keep business handles and callbacks alive through Client drainage, with bounded cleanup on exceptions too.
struct Cleanup {
    /// Borrow the client collection so cleanup can close and wait for all owned network work.
    std::vector<comet::Client>& clients;

    ~Cleanup() {
        for (auto& client : clients) {
            client.close();
        }
        for (auto& client : clients) {
            if (!client.wait(10s)) {
                std::terminate();
            }
        }
    }
};

/// Advance a writer only after a real acknowledgment; timeouts and refusals fail instead of contributing successful throughput.
void completed(auto result) {
    if (!result) {
        throw std::runtime_error("SDK operation failed, code=" + std::to_string(static_cast<int>(result.error().code)));
    }
}

/// Own each payload independently; its first eight bytes carry the sequence and its remaining bytes are fixed padding.
std::vector<std::uint8_t> content(std::size_t bytes, std::uint64_t version) {
    std::vector<std::uint8_t> result(bytes, 42);
    std::memcpy(result.data(), &version, sizeof(version));
    return result;
}

/// Validated scenario options are recorded together by the runner.
struct Options {
    /// Ready Stars; round-robin writers and readers use every supplied endpoint.
    std::vector<std::string> endpoints;
    /// A dash disables business TLS; otherwise this names the fixture CA file.
    std::string ca;
    /// Empty disables business authentication; otherwise read only the current fixture's private secret file.
    std::vector<std::uint8_t> secret;
    /// True selects Catalog; false selects Ephemeris.
    bool catalog{};
    /// 1..500 active objects, including infrequently updated background records.
    std::size_t records{};
    /// Payload size, 16..4096 bytes.
    std::size_t bytes{};
    /// Fixed Ephemeris attribute size, 0..65536 bytes.
    std::size_t attr{};
    /// 1..50 complete scope subscriptions distributed across the selected Stars.
    std::size_t watchers{};
    /// 1..32 writers, each fixed to one object with at most one in-flight write.
    std::size_t writers{};
    /// Measurement window, 2..30 seconds, excluding setup and cleanup.
    unsigned seconds{};
    /// Fixed lease duration, 1000..600000 milliseconds.
    unsigned ttl{};
    /// Zero selects closed loop; otherwise schedule this many aggregate writes per second and include send-queue delay.
    unsigned rate{};
};

/// Use the public native SDK and actual Star commit/replication/stream paths, without substituting a benchmark-only stub.
void run(const Options& options) {

    std::vector<comet::Client> clients;            // One writer client and one reader client per Star.
    const Cleanup cleanup{clients};                // Establish cleanup before constructing business objects so cores still drain during exception unwinding.
    const comet::Scope scope{"measure", "stream"}; // The runner creates a fresh cluster for each sample.
    auto open = [&](const std::string& endpoint) {
        comet::Client::Options settings;
        settings.endpoints = {endpoint};
        settings.auth = !options.secret.empty();
        settings.key = settings.auth ? "performance" : "";
        settings.secret = options.secret;
        settings.tls = options.ca != "-";
        settings.ca = settings.tls ? options.ca : "";
        settings.readers = 64;
        auto result = comet::Client::open(std::move(settings));
        Measure::require(result.has_value());
        clients.push_back(std::move(*result));
    };
    for (const auto& endpoint : options.endpoints) {
        open(endpoint);
    }
    for (const auto& endpoint : options.endpoints) {
        open(endpoint);
    }

    // Create the complete background set through real factories and retain Beacons for ordinary automatic renewal.
    std::vector<comet::Publisher> publishers;
    std::vector<comet::Beacon> beacons;
    std::vector<std::string> keys;
    for (std::size_t index = 0; index < options.records; ++index) {
        auto& writer = clients[index % options.endpoints.size()]; // Background records and hot keys retain their local source.
        if (options.catalog) {
            keys.push_back("key-" + std::to_string(index));
            auto result = writer.publisher(scope);
            Measure::require(result.has_value());
            publishers.push_back(std::move(*result));
            Measure::require(publishers.back().update(keys.back(), content(options.bytes, 1), std::chrono::milliseconds(options.ttl), std::chrono::milliseconds(options.ttl / 3)).has_value());
        } else {
            auto result = writer.beacon(scope, std::vector<std::uint8_t>(options.attr, 17), content(options.bytes, 1), std::chrono::milliseconds(options.ttl), std::chrono::milliseconds(options.ttl / 3));
            Measure::require(result.has_value());
            beacons.push_back(std::move(*result));
        }
    }
    if (!options.catalog) {
        until([&] { return std::ranges::all_of(beacons, [](const auto& beacon) { const auto state = beacon.state(); return state.phase == comet::Beacon::Phase::Ready && state.identity.has_value(); }); });
        for (const auto& beacon : beacons) {
            keys.push_back(beacon.state().identity->uuid);
        }
    }

    std::vector<comet::Subscriber> subscribers;                                                                             // Callbacks report complete Views, including SDK installation and notification costs in the sample.
    std::vector<comet::Observer> observers;                                                                                 // Each subscription owns its installed Attr/Data instead of sharing an artificial application projection.
    const auto delivery = std::make_shared<Delivery>(keys, options.writers, options.watchers, options.bytes, options.attr); // Callbacks own their confirmation state and never borrow this function's unwound stack.
    for (std::size_t index = 0; index < options.watchers; ++index) {
        auto& client = clients[options.endpoints.size() + index % options.endpoints.size()]; // Observe all local and replicated sources.
        if (options.catalog) {
            comet::Subscriber::Options settings; // SDK callbacks run outside SDK locks and must not wait on network or other business objects.
            settings.changed = [delivery, index](comet::Subscriber::View view) { delivery->receive(index, view); };
            auto result = client.subscriber(scope, {}, std::move(settings));
            Measure::require(result.has_value());
            subscribers.push_back(std::move(*result));
        } else {
            comet::Observer::Options settings;
            settings.changed = [delivery, index](comet::Observer::View view) { delivery->receive(index, view); };
            auto result = client.observer(scope, {}, std::move(settings));
            Measure::require(result.has_value());
            observers.push_back(std::move(*result));
        }
    }
    until([&] { return std::ranges::all_of(subscribers, [&](const auto& item) { return item.watch().state() == comet::Subscriber::State::Ready && item.watch().size() == options.records; }) && std::ranges::all_of(observers, [&](const auto& item) { return item.select().state() == comet::Observer::State::Ready && item.select().size() == options.records; }); });

    // A 200 ms warmup drains initial handshakes/streams; report native microbenchmarks and network scenarios separately.
    std::this_thread::sleep_for(200ms);
    std::mutex gate;
    std::exception_ptr failure;                                // Retain the first worker failure and rethrow it after joining.
    std::vector<std::size_t> writes(options.endpoints.size()); // Completed writes per source; merged under gate after each worker exits.
    std::vector<std::int64_t> acknowledged;                    // Nanoseconds from scheduled arrival to commit acknowledgment.
    std::vector<std::int64_t> installed;                       // Nanoseconds from scheduled arrival to installation at every subscription.
    const auto begin = Measure::Clock::now() + 100ms;          // Use one common start time for all workers.
    const auto end = begin + std::chrono::seconds(options.seconds);
    std::vector<std::jthread> workers; // Join within this scope before destroying handles borrowed by workers.
    for (std::size_t worker = 0; worker < options.writers; ++worker) {
        workers.emplace_back([&, worker] {
            try {
                std::vector<std::int64_t> receipts, views; // Keep samples thread-local during measurement.
                receipts.reserve(10000);
                views.reserve(10000);
                std::this_thread::sleep_until(begin);
                for (std::uint64_t index = 0; options.rate ? index * options.writers + worker < static_cast<std::uint64_t>(options.rate) * options.seconds : Measure::Clock::now() < end; ++index) {
                    const auto planned = options.rate ? begin + std::chrono::nanoseconds(static_cast<std::int64_t>((index * options.writers + worker) * 1000000000ULL / options.rate)) : Measure::Clock::now(); // Fixed arrivals retain their original scheduled time, including queueing delay.
                    std::this_thread::sleep_until(planned);
                    Measure::require(Measure::Clock::now() < end + 30s); // Bound overload rather than draining an unlimited backlog.
                    const auto version = index + 2;                      // Start at one and increase monotonically without reuse for this writer.
                    auto value = content(options.bytes, version);        // Payload construction belongs to the end-to-end window.
                    if (options.catalog) {
                        Measure::require(publishers[worker].update(keys[worker], std::move(value), std::chrono::milliseconds(options.ttl)).has_value());
                    } else {
                        completed(beacons[worker].update(std::move(value)));
                    }
                    receipts.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Measure::Clock::now() - planned).count());

                    // Wait for the slowest subscriber; closed-loop throughput measures complete visibility, not maximum server admission.
                    delivery->wait(worker, version);
                    views.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Measure::Clock::now() - planned).count());
                }
                const std::lock_guard lock(gate); // Merge after worker completion so allocation does not affect that worker's operation latency.
                writes[worker % options.endpoints.size()] += views.size();
                acknowledged.insert(acknowledged.end(), receipts.begin(), receipts.end());
                installed.insert(installed.end(), views.begin(), views.end());
            } catch (...) {
                const std::lock_guard lock(gate);
                if (!failure) {
                    failure = std::current_exception();
                }
            }
        });
    }
    workers.clear();
    if (failure) {
        std::rethrow_exception(failure);
    }
    const auto elapsed = std::chrono::duration<double>(Measure::Clock::now() - begin).count(); // Include final drainage and sampling-loop overhead in elapsed time.
    const auto count = installed.size();                                                       // Count only operations with successful commit and visibility at every subscription.
    Measure::require(count > 0);
    if (options.writers >= options.endpoints.size()) {
        Measure::require(std::ranges::all_of(writes, [](auto value) { return value != 0; }));
    }
    std::cout << "{\"topology\":\"distributed-writers-v1\",\"writes\":[";
    for (std::size_t index = 0; index < writes.size(); ++index) {
        std::cout << (index ? "," : "") << writes[index];
    }
    std::cout << "]}\n";
    Measure::report("comet.commit", std::move(acknowledged), elapsed, count);
    Measure::report("comet.visible", std::move(installed), elapsed, count);
    for (const auto& client : clients) {
        Measure::require(client.exceptions() == 0);
    }
}
} // namespace

int main(int count, char** arguments) {
    try {
        Measure::require(count == 12 || count == 13);
        Options options;
        std::string endpoints(arguments[1]); // Reject empty endpoints in the comma-separated loopback address list.
        Measure::require(!endpoints.empty() && endpoints.back() != ',');
        for (std::size_t offset = 0; offset < endpoints.size();) {
            const auto next = endpoints.find(',', offset);
            options.endpoints.push_back(endpoints.substr(offset, next - offset));
            Measure::require(!options.endpoints.back().empty());
            offset = next == std::string::npos ? endpoints.size() : next + 1;
        }
        options.ca = arguments[2];
        if (count == 13) {
            std::ifstream file(arguments[12], std::ios::binary); // Accept only the fixture's 32-byte secret and never log it.
            options.secret.resize(32);
            Measure::require(static_cast<bool>(file.read(reinterpret_cast<char*>(options.secret.data()), 32)) && file.peek() == std::char_traits<char>::eof());
        }
        options.catalog = std::string_view(arguments[3]) == "catalog";
        Measure::require(options.catalog || std::string_view(arguments[3]) == "ephemeris");
        options.records = Measure::number(arguments[4], 1, 500);
        options.bytes = Measure::number(arguments[5], 16, 4096);
        options.attr = Measure::number(arguments[6], 0, 65536);
        options.watchers = Measure::number(arguments[7], 1, 50);
        options.writers = Measure::number(arguments[8], 1, 32);
        options.seconds = static_cast<unsigned>(Measure::number(arguments[9], 2, 30));
        options.ttl = static_cast<unsigned>(Measure::number(arguments[10], 1000, 600000));
        options.rate = static_cast<unsigned>(Measure::number(arguments[11], 0, 10000));
        Measure::require(options.writers <= options.records);
        Measure::require(!options.catalog || options.ttl >= (options.seconds + 120) * 1000U); // Static background records do not renew automatically; TTL must cover setup, measurement and drainage.
        run(options);
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
