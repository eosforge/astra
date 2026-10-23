// Verify shared baseline argument validation and workload relationships.
#include "check.hpp"
#include "workload.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

namespace {
// Preserve baseline diagnostics and count only successful test-owned checks, outside production benchmarks.
void check(bool condition, const char* message) {
    Workload::check(condition, message);
    CHECK(condition);
}

/// The memory fixture checks routing, handoff and failure propagation, independently of live service performance.
class Adapter {
public:
    /// Eight initial records, each with its own mutex.
    explicit Adapter(const Workload::Options& options) : options_(options) {
        for (std::size_t record = 0; record < options.records; ++record) {
            values_[record] = Workload::content(options.bytes, record, 1);
        }
    }

    /// Writers update only their assigned records; per-record locks protect concurrent sampler reads.
    void write(std::size_t record, std::uint64_t, std::vector<std::uint8_t> value) {
        const std::lock_guard lock(gates_[record]);
        values_[record] = std::move(value);
    }

    /// Map watchers to groups so both subscriptions in each group return complete data.
    void scan(std::size_t watcher, auto&& receive) {
        for (std::size_t record = watcher / options_.fanout; record < options_.records; record += options_.groups) {
            const std::lock_guard lock(gates_[record]);
            receive(std::span<const std::uint8_t>(values_[record]));
        }
    }

    void verify() {}

private:
    /// Borrow the synthetic workload configuration for this isolated adapter lifetime.
    const Workload::Options& options_;
    /// Serialize access independently for each of the eight synthetic record slots.
    std::array<std::mutex, 8> gates_;
    /// Store synthetic payloads independently of either real SDK implementation.
    std::array<std::vector<std::uint8_t>, 8> values_;
};

/// Malformed observed payloads must propagate sampler errors and leave no unjoined worker.
class Broken : public Adapter {
public:
    using Adapter::Adapter;

    void scan(std::size_t, auto&& receive) {
        receive(std::span<const std::uint8_t>{});
    }
};

/// If an observed record later disappears, the final current-view check must fail instead of trusting a historical watermark.
class Missing : public Adapter {
public:
    using Adapter::Adapter;

    void scan(std::size_t watcher, auto&& receive) {
        if (std::this_thread::get_id() != owner_) {
            Adapter::scan(watcher, std::forward<decltype(receive)>(receive));
        }
    }

private:
    /// Return empty views only to the main thread's final check while the sampler still sees data.
    const std::thread::id owner_ = std::this_thread::get_id();
};

/// Require the tested operation itself to throw; an untriggered boundary is not a passing negative case.
void rejected(auto&& action) {
    bool failed{};
    try {
        action();
    } catch (const std::invalid_argument&) {
        failed = true;
    } catch (const std::runtime_error&) {
        failed = true;
    }
    check(failed, "Expected rejection was not observed");
}
} // namespace

/// Cover both measurement modes, multiple groups/subscribers/writers, invalid numbers and payload failures.
int main() {
    try {
        for (const auto text : {"", "-1", "+1", "4294967296", "1x", " 2"}) {
            rejected([&] { static_cast<void>(Workload::number(text)); });
        }
        check(Workload::number("0") == 0 && Workload::number("4294967295") == 4294967295U, "Unsigned boundary rejected");
        rejected([] { static_cast<void>(Measure::number("4294967301", 2, 30)); });                   // Reject fractional seconds instead of truncating them to a valid integer.
        rejected([] { static_cast<void>(Measure::number("18446744073709551616", 0, UINT64_MAX)); }); // Overflow the underlying uint64 itself.
        // Every Star needs local writers; rotate consumers around the ring and cover all nodes with each scope's subscriptions.
        Workload::Options cluster{"a,b,c", true, true, 96, 3, 3, 6, 6, 32, 32, 2, 30000, 100, 1000};
        const Workload::Route route(cluster);
        for (std::size_t client = 0; client < cluster.clients; ++client) {
            check(route.producer(client) == std::array{"a", "b", "c"}[client % 3], "Producer did not cover every Star");
            check(route.consumer(client) == std::array{"b", "c", "a"}[client % 3], "Consumer was not routed across Stars");
        }
        for (const auto endpoints : {"", "a,", ",a", "a,,b", "a,a"}) {
            auto invalid = cluster;
            invalid.endpoint = endpoints;
            rejected([&] { static_cast<void>(Workload::Route(invalid)); });
        }
        // Reject missing Clients, writers or subscriptions that would leave the third node idle.
        for (const auto field : {&Workload::Options::clients, &Workload::Options::writers, &Workload::Options::fanout}) {
            auto invalid = cluster; // Break one coverage constraint at a time while keeping all other fields valid.
            invalid.*field = 2;
            rejected([&] { static_cast<void>(Workload::Route(invalid)); });
        }
        Workload::Options options{"memory", true, true, 8, 2, 2, 2, 4, 32, 32, 2, 30000, 100, 1000};
        Workload::run<Adapter>(options);
        options.visible = false;
        Workload::run<Adapter>(options);
        rejected([&] { Workload::run<Broken>(options); });
        rejected([&] { Workload::run<Missing>(options); });
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
