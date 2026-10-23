// Define common workload arguments and invariants for comparable Redis and Comet measurements.
#pragma once
#include "../measure.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <mutex>
#include <ostream>
#include <ranges>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

/// Shared application workload for both public SDK adapters, without internal-protocol access.
class Workload {
public:
    /// Use process-local monotonic time, not a comparison of service wall clocks.
    using Clock = Measure::Clock;

    /// Validate configuration at startup; only the isolated runner supplies endpoints.
    struct Options {
        /// Redis uses one address; Comet uses a fixed comma-separated Star list, not failover candidates.
        std::string endpoint;
        /// True selects dynamic Catalog data; false selects service registration.
        bool catalog{};
        /// True waits for every target to observe each write; false waits for its receipt and verifies final views after the window.
        bool visible{};

        /// Total records, 8..1024, distributed evenly across groups.
        std::size_t records{};
        /// Independent scopes, 1..8.
        std::size_t groups{};
        /// Independent subscriptions per scope, 1..32.
        std::size_t fanout{};
        /// Shared Clients on each producer/consumer side, 1..8.
        std::size_t clients{};
        /// Writers, 1..32, with at most one in-flight call per writer.
        std::size_t writers{};
        /// Complete Data size, 16..4096 bytes, including record ID and version.
        std::size_t bytes{};
        /// Fixed Attr size, 16..16384 bytes.
        std::size_t attr{};
        /// Measurement window, 2..30 seconds.
        unsigned seconds{};
        /// Automatic-renewal TTL, 1000..600000 milliseconds.
        unsigned ttl{};
        /// Aggregate scheduled writes per second; zero selects closed-loop maximum admitted load.
        unsigned rate{};
        /// Minimum interval between complete scans, 100..10000 microseconds.
        unsigned poll{};
        /// Old Selector coalescing window in milliseconds; defaults to zero, with 10 available for comparison without changing Comet.
        unsigned legacy{};
    };

    /// Each Client is fixed to one Star and consumers rotate by one node, independently of SDK endpoint selection.
    class Route {
    public:
        /// Parse once at startup; writers, clients and per-scope subscriptions must cover every node in a multinode topology.
        explicit Route(const Options& options);

        /// Assign producer Clients to nodes round-robin and retain that source for each object's lifetime.
        const std::string& producer(std::size_t client) const {
            return endpoints_[client % endpoints_.size()];
        }

        /// Shift consumers by one node and cover all nodes through fanout, checking local and remote views for each record.
        const std::string& consumer(std::size_t client) const {
            return endpoints_[(client % endpoints_.size() + 1) % endpoints_.size()];
        }

    private:
        /// Own the validated node addresses for the complete workload.
        std::vector<std::string> endpoints_;
    };

    /// Parse strict unsigned decimal arguments, rejecting signs, trailing data and overflow.
    static unsigned number(std::string_view text) {
        return static_cast<unsigned>(Measure::number(text, 0, UINT32_MAX));
    }

    /// Fixed positional arguments are recorded by the runner; cross-field constraints prevent empty groups and concurrent writers for one record.
    static Options parse(int count, char** arguments);

    /// A failed assertion or SDK call invalidates the whole sample rather than counting as completed work.
    static void check(bool value, std::string_view reason);

    /// Encode record ID and increasing version to detect updates from the wrong record.
    static std::vector<std::uint8_t> content(std::size_t bytes, std::uint64_t record, std::uint64_t version);

    /// Both adapters share this executor; Adapter owns initialization, complete writes, public-view reads and cleanup.
    template <class Adapter>
    static void run(const Options& options) {

        std::cerr << "phase=initialize\n";                                               // Phase records distinguish baseline setup failures from workload failures and are outside latency timing.
        Adapter adapter(options);                                                        // SDK objects outlive all sample threads.
        Workload work(options);                                                          // One sampler writes the observation matrix; writers read only their own record row.
        std::jthread sampler([&](std::stop_token stop) { work.sample(adapter, stop); }); // Bound shutdown and capture thread exceptions.
        work.until([&] { return work.complete(); });                                     // Require a complete initial record at every subscription before starting the window.
        std::cerr << "phase=measuring\n";
        const auto begin = Clock::now() + std::chrono::milliseconds(100); // Use a shared start gate so initialization does not inflate measured throughput.
        const auto end = begin + std::chrono::seconds(options.seconds);   // Stop new writes at the boundary while allowing the last call bounded drainage.
        std::vector<std::jthread> writers;                                // Each writer owns a disjoint record sequence.
        for (std::size_t writer = 0; writer < options.writers; ++writer) {
            writers.emplace_back([&, writer] {
                try {
                    std::vector<std::int64_t> receipts, visibility; // Thread-local samples avoid a global statistics lock during measurement.
                    receipts.reserve(32768);
                    visibility.reserve(32768);
                    std::this_thread::sleep_until(begin);
                    for (std::uint64_t operation = 0; !work.failed_.load() && (options.rate ? operation * options.writers + writer < static_cast<std::uint64_t>(options.rate) * options.seconds : Clock::now() < end); ++operation) {
                        const auto planned = options.rate ? begin + std::chrono::nanoseconds(static_cast<std::int64_t>((operation * options.writers + writer) * 1000000000ULL / options.rate)) : Clock::now(); // Fixed-rate timing includes queueing to avoid coordinated omission.
                        std::this_thread::sleep_until(planned);
                        check(Clock::now() < end + std::chrono::seconds(30), "Writer backlog timeout");
                        const auto record = writer + static_cast<std::size_t>(operation % (options.records / options.writers)) * options.writers; // Cycle through every record, including background records.
                        const auto version = ++work.versions_[record];
                        adapter.write(record, version, content(options.bytes, record, version));
                        receipts.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - planned).count());
                        if (options.visible) {
                            work.until([&] { return work.visible(record, version); });
                            visibility.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - planned).count());
                        }
                    }
                    const std::lock_guard lock(work.gate_); // Merge only at thread exit, outside per-request latency.
                    work.receipts_.insert(work.receipts_.end(), receipts.begin(), receipts.end());
                    work.visibility_.insert(work.visibility_.end(), visibility.begin(), visibility.end());
                } catch (...) {
                    work.fail();
                }
            });
        }
        writers.clear();                                                                  // Read final versions after all writers join to avoid racing their increments.
        const auto elapsed = std::chrono::duration<double>(Clock::now() - begin).count(); // The write window includes the last receipt but excludes final convergence checks.
        work.until([&] { return work.complete(); });
        sampler.request_stop();
        sampler.join();
        work.rethrow();
        work.verify(adapter); // Re-read current views after sampling; a record seen earlier may no longer exist.
        adapter.verify();     // Inspect asynchronous SDK diagnostics as well as returned business results.

        check(!work.receipts_.empty(), "Empty measurement");
        const auto count = work.receipts_.size(); // Emit results only after every call and final view passes.
        Measure::report("commit", std::move(work.receipts_), elapsed, count);
        if (options.visible) {
            Measure::report("visible", std::move(work.visibility_), elapsed, count);
        }
        std::cout << "{\"metric\":\"sampler\",\"scans\":" << work.scans_ << ",\"busy_seconds\":" << work.busy_ << ",\"poll_us\":" << options.poll << ",\"errors\":0,\"final_converged\":true}" << std::endl;
    }

private:
    /// Borrow run configuration for the complete thread lifetime.
    const Options& options_;
    /// One slot per record/subscription; zero means no initial observation yet.
    std::unique_ptr<std::atomic<std::uint64_t>[]> seen_;
    /// Each writer exclusively updates its element, starting at version one.
    std::vector<std::uint64_t> versions_;
    /// Serialize exception publication and merging thread-local timing samples.
    std::mutex gate_;
    /// Retain the first failure and rethrow it on the main thread.
    std::exception_ptr failure_;
    /// Stop other bounded work without hiding the original exception.
    std::atomic<bool> failed_{};
    /// Nanosecond samples merged at thread exit.
    std::vector<std::int64_t> receipts_, visibility_;
    /// Complete scan count, including warmup and final convergence.
    std::uint64_t scans_{};
    /// Actual elapsed scan seconds, not thread CPU time.
    double busy_{};

    /// Allocate the zeroed observation matrix once, independently of throughput.
    explicit Workload(const Options& options);

    /// Every subscription in a group must observe its record version; one successful subscription is insufficient.
    bool visible(std::size_t record, std::uint64_t version) const;

    /// Call only before writers start or after all join, when versions_ has no concurrent writer.
    bool complete() const;

    /// Bound observation waits without resending writes and propagate failure to the main thread.
    void until(auto&& predicate) {
        const auto deadline = Clock::now() + std::chrono::seconds(30); // Maximum wait budget for each phase.
        while (!predicate()) {
            rethrow();
            check(Clock::now() < deadline, "View convergence timeout");
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    }

    /// Capture the first thread exception; other workers observe stop and drain within their bounds.
    void fail();

    /// Take the statistics lock only on failure, not ordinary polling.
    void rethrow();

    /// Recheck complete final views outside the window for membership, routing, versions and payloads; seen_ is only a historical watermark.
    template <class Adapter>
    void verify(Adapter& adapter) const {

        std::vector<bool> present(options_.records * options_.fanout);
        for (std::size_t watcher = 0; watcher < options_.groups * options_.fanout; ++watcher) {
            adapter.scan(watcher, [&](std::span<const std::uint8_t> value) {
                check(value.size() == options_.bytes, "Final payload length mismatch");
                std::uint64_t record{}, version{};
                std::memcpy(&record, value.data(), sizeof(record));
                std::memcpy(&version, value.data() + sizeof(record), sizeof(version));
                check(record < options_.records && record % options_.groups == watcher / options_.fanout, "Final routing mismatch");
                check(version == versions_[record] && std::ranges::all_of(value.subspan(16), [](auto byte) { return byte == 42; }), "Final payload mismatch");
                const auto slot = record * options_.fanout + watcher % options_.fanout; // Reject duplicate logical records within a subscription.
                check(!present[slot], "Duplicate final record");
                present[slot] = true;
            });
        }

        check(std::ranges::all_of(present, [](bool value) { return value; }), "Final view lost a record");
    }

    /// Poll public views uniformly; slow scans contribute to visibility latency and busy_seconds.
    template <class Adapter>
    void sample(Adapter& adapter, std::stop_token stop) {
        try {
            while (!stop.stop_requested() && !failed_.load()) {
                const auto begin = Clock::now();
                for (std::size_t watcher = 0; watcher < options_.groups * options_.fanout; ++watcher) {
                    adapter.scan(watcher, [&](std::span<const std::uint8_t> value) {
                        check(value.size() == options_.bytes, "Invalid visible payload length");
                        std::uint64_t record{}, version{}; // Use memcpy to avoid unaligned pointer access.
                        std::memcpy(&record, value.data(), sizeof(record));
                        std::memcpy(&version, value.data() + sizeof(record), sizeof(version));
                        check(record < options_.records && record % options_.groups == watcher / options_.fanout && version > 0, "Wrong subscription routing");
                        auto& cell = seen_[record * options_.fanout + watcher % options_.fanout]; // Only the sampler updates these slots.
                        const auto previous = cell.load(std::memory_order_relaxed);
                        check(version >= previous, "Visible version regressed");
                        if (version != previous) {
                            check(std::ranges::all_of(value.subspan(16), [](auto byte) { return byte == 42; }), "Visible payload corrupted");
                            cell.store(version, std::memory_order_relaxed);
                        }
                    });
                }
                ++scans_;
                busy_ += std::chrono::duration<double>(Clock::now() - begin).count();
                std::this_thread::sleep_until(begin + std::chrono::microseconds(options_.poll));
            }
        } catch (...) {
            fail();
        }
    }
};
