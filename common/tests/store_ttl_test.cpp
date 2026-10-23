// Verify Store expiration and history boundaries under explicit lifetime settings.
#include "check.hpp"
#include "store.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <iostream>
#include <limits>
#include <map>
#include <random>
#include <set>
#include <thread>

using namespace astra;
using namespace std::chrono_literals;

namespace {
/// Deterministic Unix business-time origin; construct all times explicitly without wall-clock reads or sleeps.
constexpr auto origin = Clock::Time(1s);

/// Reject each invalid timing input independently and retain both valid endpoint values.
void testConfiguration() {

    /// Own one timing configuration and its independently specified admission result.
    struct Case {
        /// Local history age; zero disables retained history.
        Steady::duration retention;
        /// Scheduling precision, which must be positive.
        std::chrono::nanoseconds interval;
        /// Optional nonnegative business-time anchor.
        std::optional<Clock::Time> initial;
        /// Expected constructor outcome, independent of Store's predicate.
        bool accepted;
    };

    // cases vary one field at a time around otherwise valid input.
    const std::array cases{
        Case{10min, 1ns, {}, true},
        Case{10min, 1ns, Clock::Time{}, true},
        Case{10min, 1ns, origin, true},
        Case{10min, 1ns, Clock::Time::max(), true},
        Case{10min, 1ns, Clock::Time(-1ns), false},
        Case{10min, 1ns, Clock::Time::min(), false},
        Case{10min, 0ns, origin, false},
        Case{10min, -1ns, origin, false},
        Case{10min, std::chrono::nanoseconds::max(), origin, true},
        Case{-1ns, 1ns, origin, false},
        Case{0ns, 1ns, origin, true},
        Case{Steady::duration::max(), 1ns, origin, true},
    };
    for (const auto& entry : cases) {
        // rejected changes only for the documented parameter error, never an unrelated exception.
        bool rejected = false;
        try {
            // store must start empty without manufacturing a commit or requiring a clock read.
            Store store(1000, entry.retention, entry.interval, entry.initial);
            CHECK(store.version() == 0);
            CHECK(store.snapshot()->data.empty());
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected != entry.accepted);
    }
}

/// Retain sub-tick remainder; ceil deadlines to ticks, and equal/backward time must not advance again.
void testPrecisionAndClock() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(1000, 10min, 10ms, origin);
    store.put("boundary", {1}, origin + 10ms);
    store.put("fraction", {2}, origin + 10ms + 1ns);
    store.put("permanent", {3});
    store.tick(origin + 9ms);
    CHECK(store.version() == 3);
    store.tick(origin + 10ms);
    CHECK(store.version() == 4 && !store.snapshot()->data.contains("boundary"));
    CHECK(store.snapshot()->data.contains("fraction"));
    store.tick(origin + 10ms);
    store.tick(origin - 1ms);
    store.tick(origin + 19ms);
    CHECK(store.version() == 4);
    store.tick(origin + 20ms);
    CHECK(store.version() == 5 && store.snapshot()->data.size() == 1);
    CHECK(store.snapshot()->data.contains("permanent"));
}

/// Schedule from Store's advanced boundary without adding current clock-read or driver delay to absolute leases.
void testRenewalAndCatchup() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(1000, 10min, 1ms, origin);
    store.put("renew", {1}, origin + 5ms);
    store.put("early", {2}, origin + 20ms);
    store.put("cancel", {3}, origin + 4ms);
    store.tick(origin + 2ms);
    store.put("renew", {4}, origin + 10ms);
    store.put("early", {5}, origin + 3ms);
    store.put("cancel", {6});
    store.tick(origin + 3ms);
    CHECK(!store.snapshot()->data.contains("early"));
    store.tick(origin + 5ms);
    CHECK(store.snapshot()->data.at("renew").value->front() == 4);
    CHECK(store.snapshot()->data.at("cancel").value->front() == 6);
    // Deltas retain absolute Unix deadlines; empty is permanent and maximum integer is valid finite time.
    // Complete suffix checked by Delete count and version boundaries, independent of intra-batch Key order.
    const auto changes = store.extract(3);
    CHECK(changes.deltas[0].deadline == origin + 10ms);
    CHECK(!changes.deltas[2].deadline);
    store.put("overdue", {7}, origin + 1ms);
    store.put("later", {8}, origin + 40ms);
    // Pre-catch-up sequence; whole-batch expiry increments version once.
    const auto before = store.version();
    store.tick(origin + 50ms);
    CHECK(store.version() == before + 1);
    // Complete expiry Delete batch shares one version and carries no finite deadlines.
    const auto expired = store.extract(before);
    CHECK(expired.deltas.size() == 3);
    for (const auto& delta : expired.deltas) {
        CHECK(delta.deleted && delta.version == before + 1 && !delta.deadline);
    }
    CHECK(store.snapshot()->data.size() == 1 && store.snapshot()->data.contains("cancel"));
}

/// Map growth preserves hooks/Key addresses; delete/recreate cannot trigger an old lease.
void testRehashAndRecreation() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(0, 10min, 1ms, origin);
    for (unsigned index = 0; index < 2048; ++index) {
        store.put("ttl/" + std::to_string(index), {1}, origin + 5ms);
    }
    store.remove("ttl/0");
    store.put("ttl/0", {2}, origin + 10ms);
    store.tick(origin + 5ms);
    CHECK(store.snapshot()->data.size() == 1 && store.snapshot()->data.at("ttl/0").value->front() == 2);
    store.tick(origin + 10ms);
    CHECK(store.snapshot()->data.empty());
    store.put("ttl/0", {3}, origin + 11ms);
    store.tick(origin + 11ms);
    CHECK(store.snapshot()->data.empty());
}

/// Signed-extreme distances must not overflow; a large interval covers boundaries in two ticks.
void testExtremeClock() {

    // Maximum nanosecond duration compresses time-arithmetic coverage into a few ticks.
    const auto interval = std::chrono::nanoseconds::max();
    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(1000, 10min, interval, Clock::Time{});
    store.put("last", {1}, Clock::Time::max());
    store.put("permanent", {2});
    store.tick(Clock::Time::max() - 1ns);
    CHECK(store.version() == 2);
    store.tick(Clock::Time::max());
    CHECK(store.version() == 3 && store.snapshot()->data.size() == 1);
    CHECK(store.snapshot()->data.contains("permanent"));
    // Maximum integer is a valid finite deadline, not a permanent sentinel.
    Store distant(1000, 10min, 1ns, origin);
    distant.put("distant", {1}, origin + std::chrono::nanoseconds(static_cast<std::int64_t>(Store::Timer::limit + 1)));
    distant.tick(origin + 5ns);
    CHECK(distant.version() == 1 && distant.snapshot()->data.contains("distant"));
}

/// Writes, catch-up, and snapshots contend on one Store lock; every intrusive-hook access must share that boundary.
void testConcurrentTtl() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(1000, 10min, 1ms, origin);
    // Each exception slot has one writer and is read after join; finished controls readers only.
    std::array<std::exception_ptr, 2> errors{};
    // Writer-completion flag; join both workers before checking exceptions even after readers stop.
    std::atomic_bool finished{false};
    // Continuously updates short leases and permanent entries; stores exceptions in errors[0] without escaping thread entry.
    std::jthread writer([&] {
        try {
            for (unsigned index = 0; index < 512; ++index) {
                store.put("ttl/" + std::to_string(index), {1}, origin + 1ms);
                store.put("live", {2});
            }
        } catch (...) {
            errors[0] = std::current_exception();
        }
        finished.store(true);
    });
    // Advances 1..200 ms concurrently, saving exceptions in errors[1]; sleeps do not determine TTL.
    std::jthread ticker([&] {
        try {
            for (unsigned step = 1; step <= 200; ++step) {
                store.tick(origin + std::chrono::milliseconds(step));
            }
        } catch (...) {
            errors[1] = std::current_exception();
        }
    });
    do {
        // Owns one captured complete version; concurrent writes cannot change it during checks.
        const auto snapshot = store.snapshot();
        for (const auto& [key, value] : snapshot->data) {
            CHECK(value.value && value.value->size() == 1 && value.value->front() == (key == "live" ? 2 : 1));
        }
    } while (!finished.load());
    writer.join();
    ticker.join();
    for (const auto& error : errors) {
        if (error) {
            std::rethrow_exception(error);
        }
    }
    store.tick(origin + 2s);
    CHECK(store.snapshot()->data.size() == 1 && store.snapshot()->data.contains("live"));
}

/// Catch-up beyond the former budget completes at once; sub-tick deadlines remain pending and equal/backward time creates no commit.
void testCompleteCatchup() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(1000, 10min, 1ms, origin);
    store.put("boundary", {1}, origin + 1024ms);
    store.put("next", {2}, origin + 1025ms);
    store.put("later", {3}, origin + 2500ms);
    store.put("fraction", {4}, origin + 3000ms + 1ns);
    store.put("permanent", {5});
    // 3000 whole millisecond ticks plus 500 ns remainder checks complete catch-up without premature expiry.
    const auto target = origin + 3000ms + 500ns;
    store.tick(target);
    // Owns one captured complete version; concurrent writes cannot change it during checks.
    const auto snapshot = store.snapshot();
    CHECK(snapshot->version == 6 && snapshot->data.size() == 2);
    CHECK(snapshot->data.contains("fraction") && snapshot->data.contains("permanent"));
    // Complete suffix checked by Delete count and version boundaries, independent of intra-batch Key order.
    const auto changes = store.extract(5);
    CHECK(!changes.stale && changes.version == 6 && changes.deltas.size() == 3);
    // Initially empty set detects repeated returned Delete Keys.
    std::set<std::string> keys;
    for (const auto& delta : changes.deltas) {
        CHECK(delta.deleted && !delta.value && delta.version == 6);
        CHECK(keys.insert(delta.key).second);
    }
    CHECK(keys.contains("boundary") && keys.contains("next") && keys.contains("later"));
    store.tick(target);
    store.tick(origin);
    CHECK(store.snapshot() == snapshot);
    store.tick(origin + 3001ms);
    CHECK(store.version() == 7 && store.snapshot()->data.size() == 1);
    CHECK(store.snapshot()->data.contains("permanent"));
}

/// Models one hour without driving; five-second absolute leases written before/after catch-up share the same actual expiry.
void testPauseAndNewLease() {

    // Independent Store with explicit history/tick settings, without host wall-clock business time.
    Store store(100, Steady::duration::max(), 10ms, origin);
    // Synthetic Unix time after one-hour suspension, without actual waiting.
    const auto resumed = origin + 1h;
    // Absolute deadline five seconds after resume; writes before and after catch-up share it.
    const auto deadline = resumed + 5s;
    store.put("old", {1}, origin + 1s);
    store.put("before-catchup", {2}, deadline);
    store.tick(resumed);
    CHECK(store.version() == 3 && store.snapshot()->data.size() == 1);
    CHECK(store.snapshot()->data.contains("before-catchup"));
    store.put("after-catchup", {3}, deadline);
    store.tick(deadline - 1ns);
    CHECK(store.version() == 4 && store.snapshot()->data.size() == 2);
    store.tick(deadline);
    CHECK(store.version() == 5 && store.snapshot()->data.empty());
    // Complete suffix checked by Delete count and version boundaries, independent of intra-batch Key order.
    const auto changes = store.extract(4);
    CHECK(!changes.stale && changes.deltas.size() == 2);
    for (const auto& delta : changes.deltas) {
        CHECK(delta.deleted && delta.version == 5);
    }
}

/// Independent map/commit log checks random writes, deletes, catch-up, and resumption with a reproducible seed.
void testStoreModel() {

    // Eight retained history batches in model and Store, not a Key-count limit.
    constexpr std::uint64_t capacity = 8;
    for (const auto seed : {11U, 29U, 71U}) {
        // Independent Store with explicit history/tick settings, without host wall-clock business time.
        Store store(capacity, Steady::duration::max(), 1ms, origin);
        // Independent per-Key payload/expiry model; UINT64_MAX is a permanent sentinel inside this model only.
        std::map<std::string, std::pair<Store::Buffer, std::uint64_t>> state;
        // Complete model commit log, separate from bounded Store history, checks arbitrary valid cursors.
        std::vector<Store::Delta> log;
        // Model batch sequence, initially zero; same-tick multi-Key expiry increments once.
        std::uint64_t version = 0;
        // Advanced model milliseconds, initially zero and changed only by random advancement.
        std::uint64_t observed = 0;
        std::mt19937_64 random(seed);
        // Converts model ticks to Unix milliseconds at the same origin without system-clock reads.
        const auto at = [](std::uint64_t tick) { return origin + std::chrono::milliseconds(static_cast<std::int64_t>(tick)); };
        // Borrows model state/version to compare complete snapshot contents and sequence.
        const auto checkSnapshot = [&](const auto& snapshot) {
            CHECK(snapshot->version == version && snapshot->data.size() == state.size());
            for (const auto& [key, item] : state) {
                CHECK(snapshot->data.contains(key) && *snapshot->data.at(key).value == item.first);
            }
        };
        for (unsigned step = 0; step < 2000; ++step) {
            // Selects among 32 Keys to force frequent replacement, deletion, and node reuse.
            const auto key = "model/" + std::to_string(random() % 32);
            switch (random() % 4) {
            case 0: {
                const Store::Buffer value{static_cast<std::uint8_t>(random() % 256)};
                // One quarter use model permanent sentinel; others expire 0..23 ticks after observed.
                const auto expiry = random() % 4 == 0 ? UINT64_MAX : observed + random() % 24;
                // Converts permanent sentinel to empty deadline, finite ticks to absolute Unix time.
                const std::optional<Clock::Time> deadline = expiry == UINT64_MAX ? std::nullopt : std::optional{at(expiry)};
                store.put(key, value, deadline);
                state.insert_or_assign(key, std::pair{value, expiry});
                log.emplace_back(key, std::make_shared<const Store::Buffer>(value), false, ++version, deadline);
                break;
            }
            case 1:
                store.remove(key);
                if (state.erase(key) != 0) {
                    log.emplace_back(key, nullptr, true, ++version);
                }
                break;
            case 2: {
                // Previous tick before advancement; same-tick calls cannot expire newly written zero-delay values.
                const auto previous = observed;
                observed += random() % 7;
                store.tick(at(observed));
                // Initially false; first actual expiry starts a batch and later Deletes share its version.
                bool changed = false;
                if (observed != previous) {
                    for (auto entry = state.begin(); entry != state.end();) {
                        if (entry->second.second <= observed) {
                            if (!changed) {
                                ++version;
                                changed = true;
                            }
                            log.emplace_back(entry->first, nullptr, true, version);
                            entry = state.erase(entry);
                        } else {
                            ++entry;
                        }
                    }
                }
                break;
            }
            default:
                store.tick(at(observed));
                store.tick(at(observed) - 1ms);
                break;
            }
            CHECK(store.version() == version);
            // Owns one captured complete version; concurrent writes cannot change it during checks.
            const auto snapshot = store.snapshot();
            checkSnapshot(snapshot);
            CHECK(store.snapshot() == snapshot);

            // Random cursor covers valid suffixes, insufficient history, and one-version future positions.
            const auto cursor = random() % 4 == 0 ? version + 1 : version - random() % std::min(version + 1, capacity + 2);
            // Actual extraction result; check stale before comparing records.
            const auto result = store.extract(cursor);
            // Model batch count determines resumption floor, which remains a valid cursor itself.
            const auto oldest = version > capacity ? version - capacity : 0;
            CHECK(result.version == version && result.stale == (cursor > version || cursor < oldest));
            if (result.stale) {
                CHECK(result.deltas.empty());
                continue;
            }

            // Expected version/Key pairs ignore intra-batch ordering while rejecting duplicates or omissions.
            std::set<std::pair<std::uint64_t, std::string>> remaining;
            for (const auto& delta : log) {
                if (delta.version > cursor) {
                    CHECK(remaining.emplace(delta.version, delta.key).second);
                }
            }

            // Tracks nondecreasing returned versions, initially the acknowledged cursor.
            auto previous = cursor;
            for (const auto& delta : result.deltas) {
                CHECK(delta.version >= previous && remaining.erase({delta.version, delta.key}) == 1);
                previous = delta.version;
                // Matches version/Key in the independent complete model log, never derives expectations from implementation output.
                const auto expected = std::ranges::find_if(log, [&](const auto& item) { return item.version == delta.version && item.key == delta.key; });
                CHECK(expected != log.end() && delta.deleted == expected->deleted && delta.deadline == expected->deadline);
                CHECK(static_cast<bool>(delta.value) == static_cast<bool>(expected->value));
                if (delta.value) {
                    CHECK(*delta.value == *expected->value);
                }
            }
            CHECK(remaining.empty());
        }
    }
}
} // namespace

/// Isolated process runs all boundary cases; assertion failure returns nonzero.
int main() {

    try {
        testConfiguration();
        testPrecisionAndClock();
        testRenewalAndCatchup();
        testRehashAndRecreation();
        testExtremeClock();
        testConcurrentTtl();
        testCompleteCatchup();
        testPauseAndNewLease();
        testStoreModel();
        std::cout << "Store TTL clock, renewal, batch, rehash and extreme boundaries passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
