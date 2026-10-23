// Verify internal Store state, history, and snapshot behavior.
#include "check.hpp"
#include "store.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace astra;
using namespace std::chrono_literals;

namespace {

/// Writes/deletes preserve delivered snapshots; same versions reuse cache and by-value inputs isolate caller buffers.
void testPutAndRemove() {

    // Default history capacity; initial version must be zero.
    Store store;
    CHECK(store.version() == 0);

    // Caller retains and mutates the original input to verify by-value buffer isolation.
    std::vector<std::uint8_t> payload1{1, 2, 3};
    store.put("key1", payload1);
    payload1[0] = 9;

    CHECK(store.version() == 1);

    // Retains old version across deletion to check cache identity and immutable contents.
    const auto snapshot1 = store.snapshot();
    CHECK(snapshot1->version == 1);
    CHECK(snapshot1->data.size() == 1);
    CHECK(snapshot1->data.at("key1").value->at(0) == 1);
    CHECK(store.snapshot() == snapshot1);

    store.remove("key1");
    CHECK(store.version() == 2);

    // Current post-deletion snapshot must not modify snapshot1's map.
    const auto snapshot2 = store.snapshot();
    CHECK(snapshot2->version == 2);
    CHECK(snapshot2->data.size() == 0);
    CHECK(snapshot1->data.size() == 1);
    store.remove("key1");
    CHECK(store.version() == 2);
}

/// Finite deadlines expire at equality; permanent data survives finite-lease cleanup.
void testEvictExpired() {

    // Deterministic Unix origin for finite and permanent entries.
    const auto now = Clock::Time{};
    // Independent Store with explicit history and time rules for this scenario.
    Store store(1000, 10min, 1s, now);

    store.put("key1", {1}, now + 10s);
    store.put("key2", {2});

    CHECK(store.version() == 2);

    store.tick(now + 5s);
    CHECK(store.version() == 2);

    store.tick(now + 10s);
    CHECK(store.version() == 3);

    // At exact deadline, only the finite Key is removed.
    const auto snapshot = store.snapshot();
    CHECK(snapshot->version == 3);
    CHECK(snapshot->data.size() == 1);
    CHECK(snapshot->data.find("key2") != snapshot->data.end());
    CHECK(snapshot->data.find("key1") == snapshot->data.end());

    // Extreme now preserves permanent data while near-maximum finite deadlines expire.
    // Two ticks near the extreme cover the boundary without billions of empty catch-up ticks.
    Store edge(1000, 10min, Steady::duration{1}, Clock::Time::max() - Steady::duration{2});
    edge.put("permanent", {2});
    edge.put("last_finite", {3}, Clock::Time::max() - Steady::duration{1});
    edge.tick(Clock::Time::max());
    CHECK(edge.version() == 3);
    CHECK(edge.snapshot()->data.size() == 1);
    CHECK(edge.snapshot()->data.contains("permanent"));
    edge.tick(Clock::Time::max());
    CHECK(edge.version() == 3);
}

/// Retention floor is the last complete retired batch; future cursors explicitly require snapshots.
void testExtractSinceAndHistoryTrim() {

    // Two-batch capacity; third commit advances the oldest resumable position to 1.
    Store store(2);

    store.put("k1", {});
    store.put("k2", {});
    store.remove("k1");

    // Contains only the final Delete, without replaying the cursor's own batch.
    const auto res1 = store.extract(2);
    CHECK(!res1.stale);
    CHECK(res1.version == 3);
    CHECK(res1.deltas.size() == 1);
    CHECK(res1.deltas[0].deleted);

    // Exactly at the retention floor; still returns the next two complete batches.
    const auto res2 = store.extract(1);
    CHECK(!res2.stale);
    CHECK(res2.version == 3);
    CHECK(res2.deltas.size() == 2);

    // Outside retained history; must request a snapshot instead of returning an incomplete suffix.
    const auto res3 = store.extract(0);
    CHECK(res3.stale);

    // Future uncommitted cursor explicitly falls back like insufficient history.
    const auto resFuture = store.extract(100);
    CHECK(resFuture.stale);
}

/// Capacity cannot split one expiry batch; old Delete retirement cannot affect a rewritten Key.
void testBatchesAndRecreation() {

    // Capacity counts batches, not records; both Deletes in one batch must remain.
    Store store(1, 10min, 1ms, Clock::Time{});
    store.put("a", {1}, Clock::Time{});
    store.put("b", {2}, Clock::Time{});
    store.tick(Clock::Time{} + 1ms);
    // Owned history copy remains valid after later trimming.
    const auto expired = store.extract(2);
    CHECK(!expired.stale && expired.version == 3 && expired.deltas.size() == 2);
    // Key order is unspecified, but batch version and Delete meaning must match.
    for (const auto& delta : expired.deltas) {
        CHECK(delta.deleted && delta.version == 3);
    }
    store.put("a", {3});
    CHECK(store.extract(2).stale);
    CHECK(store.snapshot()->data.at("a").value->at(0) == 3);
    CHECK(!store.snapshot()->data.contains("b"));

    // Zero-history mode keeps current state; only a cursor at the current commit can skip a snapshot.
    // Immediate history retirement must preserve live values.
    Store noHistory(0);
    CHECK(!noHistory.extract(0).stale);
    noHistory.put("a", {1});
    CHECK(noHistory.extract(0).stale);
    CHECK(!noHistory.extract(1).stale);
    noHistory.remove("a");
    noHistory.put("a", {2});
    CHECK(noHistory.snapshot()->data.at("a").value->at(0) == 2);

    // Delete/recreate/delete one Key, then retire its first Delete independently of empty-node caching.
    Store reused(2);
    reused.put("a", {1});
    reused.remove("a");
    reused.put("a", {2});
    reused.remove("a");
    CHECK(reused.snapshot()->data.empty());
    reused.remove("a");
    CHECK(reused.version() == 4);
    reused.put("a", {3});
    // Replay must retain second Delete and final recreation regardless of cached-node reclamation timing.
    const auto replay = reused.extract(3);
    CHECK(!replay.stale && replay.deltas.size() == 2);
    CHECK(replay.deltas.front().deleted && replay.deltas.front().version == 4);
    CHECK(!replay.deltas.back().deleted && replay.deltas.back().value->front() == 3);
}

/// Checks deque-segment lookup, exact cursor bounds, and long suffixes without iterator-layout assumptions.
void testLongHistorySuffix() {

    // 1128 commits retain the last 1000; Keys repeat while sequence numbers increase.
    Store store(1000);
    // Version encodes Key and payload to detect missing, repeated, or reordered batches independently.
    for (std::uint64_t version = 1; version <= 1128; ++version) {
        store.put("key/" + std::to_string(version % 32), {static_cast<std::uint8_t>(version % 251)});
    }
    CHECK(store.extract(127).stale);
    CHECK(store.extract(1129).stale);
    // Cursors cover retention floor, middle, one-batch lag, and synchronized positions.
    for (const std::uint64_t cursor : {128U, 129U, 499U, 1000U, 1127U, 1128U}) {
        // Must cover exactly (cursor, 1128], respecting history window and commit barrier.
        const auto result = store.extract(cursor);
        CHECK(!result.stale && result.version == 1128);
        CHECK(result.deltas.size() == 1128 - cursor);
        // Independent externally visible commit sequence, not the tested container's lookup algorithm.
        auto expected = cursor + 1;
        for (const auto& delta : result.deltas) {
            CHECK(delta.version == expected && !delta.deleted);
            CHECK(delta.key == "key/" + std::to_string(expected % 32));
            CHECK(delta.value->at(0) == expected % 251);
            ++expected;
        }
    }
}

/// Extraction budget includes arrays and long Keys; rejection preserves history/snapshots without presenting a partial batch as complete.
void testExtractBudget() {

    // Long Key forces name copying; large shared Value does not consume this copy budget.
    Store store;
    const std::string key(256, 'k');
    store.put(key, Store::Buffer(4096, 7));
    // Retains pre-extraction contents through failures and later writes.
    const auto previous = store.snapshot();
    // Exact minimum cost of one Delta element and complete NUL-terminated Key bytes.
    const auto exact = sizeof(Store::Delta) + key.size() + 1;
    // Exact-budget extraction checks Key charges and shared Value ownership together.
    const auto extracted = store.extract(0, exact);
    CHECK(extracted.version == 1 && extracted.deltas.size() == 1 && extracted.deltas.front().value == previous->data.at(key).value);
    for (const auto budget : {std::size_t{0}, sizeof(Store::Delta) - 1, exact - 1}) {
        // Initially false; set only for expected argument or budget exceptions.
        bool rejected = false;
        try {
            static_cast<void>(store.extract(0, budget));
        } catch (const std::length_error&) {
            rejected = true;
        }
        CHECK(rejected && store.version() == 1 && store.snapshot() == previous);
    }
    CHECK(store.extract(0, exact).deltas.size() == 1);
    CHECK(store.extract(1, 0).deltas.empty() && !store.extract(1, 0).stale);
    CHECK(store.extract(2, 0).stale);
    // All batches share one budget; skipping acknowledged prefixes lets the suffix fit within the same limit.
    store.put(key, {8});
    // Records explicit whole-result budget failure, rejecting per-batch accounting.
    bool multipleRejected = false;
    try {
        static_cast<void>(store.extract(0, exact));
    } catch (const std::length_error&) {
        multipleRejected = true;
    }
    CHECK(multipleRejected && store.version() == 2 && previous->data.at(key).value->front() == 7);
    // After skipping the prefix, same-budget suffix contains only the second update.
    const auto suffix = store.extract(1, exact);
    CHECK(suffix.deltas.size() == 1 && suffix.deltas.front().version == 2 && suffix.deltas.front().value->front() == 8);

    // Multi-Delete TTL commits cannot acknowledge a version when budget fits only the first record.
    Store expiring(100, 10min, 1ms, Clock::Time{});
    expiring.put("a", {1}, Clock::Time{} + 1ms);
    expiring.put("b", {2}, Clock::Time{} + 1ms);
    expiring.tick(Clock::Time{} + 1ms);
    // Complete cost of two one-byte Keys in one batch; one byte less must not yield partial data.
    const auto batchBytes = 2 * (sizeof(Store::Delta) + 2);
    // Initially false; set only for expected argument or budget exceptions.
    bool rejected = false;
    try {
        static_cast<void>(expiring.extract(2, batchBytes - 1));
    } catch (const std::length_error&) {
        rejected = true;
    }
    CHECK(rejected && expiring.version() == 3);
    // Complete Delete batch; both records share one commit sequence.
    const auto complete = expiring.extract(2, batchBytes);
    CHECK(complete.deltas.size() == 2 && complete.version == 3);
    CHECK(complete.deltas[0].version == 3 && complete.deltas[1].version == 3 && complete.deltas[0].deleted && complete.deltas[1].deleted);
}

/// Returned results own Keys and payload references even after Store and its history are destroyed.
void testResultLifetime() {

    // Retain snapshot and delta outside Store scope to expose dangling borrows.
    std::shared_ptr<const Store::Snapshot> snapshot;
    // Extracted Key and Value ownership remains readable after source destruction.
    Store::Extraction delta;
    {
        // Empty Key and empty payload remain valid writes, distinct from Delete.
        Store store;
        store.put("", {});
        snapshot = store.snapshot();
        delta = store.extract(0);
        store.remove("");
    }
    CHECK(snapshot->version == 1 && snapshot->data.at("").value->empty());
    CHECK(delta.version == 1 && delta.deltas.size() == 1);
    CHECK(!delta.deltas.front().deleted && delta.deltas.front().value->empty());
}

/// One Key's payload encodes commit version; concurrent snapshots must pair exact version and contents.
void testConcurrentSnapshots() {

    // One-byte commits encode expected version directly.
    Store store;
    // Coordinates test termination only; Store synchronization must use its own lock.
    std::atomic_bool finished{false};
    // Written by writer and read after join; exceptions never escape thread entry.
    std::exception_ptr writerError;
    // jthread joins during unwinding so no worker accesses destroyed Store state.
    std::jthread writer([&] {
        try {
            // Restricts values to uint8_t range so wrap cannot hide version mismatch.
            for (std::uint16_t value = 1; value <= 200; ++value) {
                store.put("counter", {static_cast<std::uint8_t>(value)});
            }
        } catch (...) {
            writerError = std::current_exception();
        }
        finished.store(true);
    });
    do {
        // Snapshot read during writing must match the version captured in its same critical section.
        const auto snapshot = store.snapshot();
        if (snapshot->version == 0) {
            CHECK(snapshot->data.empty());
        } else {
            CHECK(snapshot->data.size() == 1);
            CHECK(snapshot->data.at("counter").value->at(0) == snapshot->version);
        }
    } while (!finished.load());
    writer.join();
    if (writerError) {
        std::rethrow_exception(writerError);
    }
    CHECK(store.snapshot()->version == 200);
}

/// History uses local elapsed age; idle ticks trim tombstones independently of business Unix time.
void testRetentionAndIdleMaintenance() {

    // Business origin with one-hour ticks avoids unnecessary empty-tick work in age-retention tests.
    const auto start = Clock::Time(1h);
    // Independent Store with explicit history and time rules for this scenario.
    Store store(100, 1h, 1h, start);
    store.put("live", {1});
    store.put("removed", {2});
    store.remove("removed");
    // Local time after setup writes; advance history age synthetically without sleeping.
    const auto written = Steady::now();
    store.tick(start - 1ns);
    CHECK(!store.extract(0).stale && store.extract(0).deltas.size() == 3);
    store.tick(start + 1h, written + 1h);
    CHECK(store.version() == 3 && store.extract(0).stale && store.extract(2).stale);
    CHECK(!store.extract(3).stale && store.extract(3).deltas.empty());
    CHECK(store.snapshot()->data.size() == 1 && store.snapshot()->data.at("live").value->front() == 1);
    store.put("removed", {3});
    // Suffix after acknowledged version verifies same-Key recreation still produces a normal write after cleanup.
    const auto changes = store.extract(3);
    CHECK(!changes.stale && changes.deltas.size() == 1 && !changes.deltas.front().deleted);
    CHECK(store.snapshot()->data.at("removed").value->front() == 3);

    Store noRetention(100, Steady::duration::zero());
    noRetention.put("live", {1});
    CHECK(noRetention.extract(0).stale && !noRetention.extract(1).stale);
    noRetention.remove("live");
    CHECK(noRetention.extract(1).stale && !noRetention.extract(2).stale);
    noRetention.put("live", {2});
    CHECK(noRetention.snapshot()->data.at("live").value->front() == 2);

    // Initially false; set only for expected argument or budget exceptions.
    bool rejected = false;
    try {
        Store invalid(100, -1ns);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Weak ownership checks cache release; old payload survives while an external snapshot retains it.
void testInvalidatedSnapshotRelease() {

    for (unsigned operation = 0; operation < 3; ++operation) {
        // Independent Store with explicit history and time rules for this scenario.
        Store store(0, 10min, 1ms, Clock::Time{});
        store.put("payload", Store::Buffer(4096, 7), Clock::Time{} + 1ms);
        // Current strong snapshot; reset distinguishes cache ownership from external readers.
        auto snapshot = store.snapshot();
        // Observes old-cache reclamation without extending lifetime.
        std::weak_ptr<const Store::Snapshot> oldSnapshot = snapshot;
        // Observes old-payload lifetime; replacement, deletion, and expiry must release invalid cache references.
        std::weak_ptr<const Store::Buffer> oldPayload = snapshot->data.at("payload").value;
        snapshot.reset();
        CHECK(!oldSnapshot.expired() && !oldPayload.expired());
        if (operation == 0) {
            store.put("payload", {8});
        } else if (operation == 1) {
            store.remove("payload");
        } else {
            store.tick(Clock::Time{} + 1ms);
        }
        CHECK(store.version() == 2 && oldSnapshot.expired() && oldPayload.expired());
    }

    // Independent Store with explicit history and time rules for this scenario.
    Store store(0);
    store.put("held", {9});
    // Current strong snapshot; reset distinguishes cache ownership from external readers.
    auto snapshot = store.snapshot();
    // Observes final payload release after external snapshot reset; weak reference owns no bytes.
    std::weak_ptr<const Store::Buffer> payload = snapshot->data.at("held").value;
    store.remove("missing");
    CHECK(store.snapshot() == snapshot);
    store.remove("held");
    CHECK(!payload.expired() && snapshot->data.at("held").value->front() == 9);
    snapshot.reset();
    CHECK(payload.expired());
}

/// Page boundaries, root growth, pruning, and multigeneration sharing preserve old views; mutable wheel nodes never enter snapshots.
void testSnapshotIndex() {

    Index index;
    // Captured empty root must remain empty through later growth and writes.
    const auto empty = index.capture();
    // Shared old payload containing byte 1.
    const auto original = std::make_shared<const Store::Buffer>(Store::Buffer{1});
    // New payload containing byte 2; pointer identity reveals accidental old-page mutation.
    const auto changed = std::make_shared<const Store::Buffer>(Store::Buffer{2});
    // Retains roots at height boundaries to force shared-page writes.
    std::vector<Index::View> checkpoints;
    // 64 leaf slots and 16 branches; retain readers before crossing 64/1024 boundaries and root expansion.
    for (std::uint64_t slot = 0; slot < 1100; ++slot) {
        CHECK(index.next() == slot);
        index.prepare(slot);
        index.set(slot, std::make_shared<const std::string>(std::to_string(slot)), {original, {}});
        if (slot == 63 || slot == 1023) {
            checkpoints.push_back(index.capture());
        }
    }

    // Pins prechange Keys, payloads, and live count.
    const auto before = index.capture();
    CHECK(empty.size() == 0 && before.size() == 1100);
    for (std::uint64_t slot = 0; slot < 1100; ++slot) {
        index.prepare(slot);
        if ((slot & 1) == 0) {
            index.erase(slot);
        } else {
            index.set(slot, {}, {changed, {}});
        }
    }

    // After deleting even slots and replacing odd slots, contains exactly 550 new values.
    const auto after = index.capture();
    CHECK(after.size() == 550);
    // Traversal count, initially zero, independently checked against View::size.
    std::size_t seen = 0;
    after.each([&](const std::string& key, const Index::Record& record) {
        CHECK(std::stoull(key) % 2 == 1 && record.value == changed);
        ++seen;
    });
    CHECK(seen == 550);
    checkpoints.push_back(before);
    for (const auto& view : checkpoints) {
        // Expected increasing slot sequence in the old snapshot, advanced per visited item.
        std::size_t slot = 0;
        view.each([&](const std::string& key, const Index::Record& record) { CHECK(key == std::to_string(slot++) && record.value == original); });
        CHECK(slot == view.size());
    }

    // Reuse deleted slots and repopulate an empty index without changing reader-retained roots.
    CHECK(index.next() == 0);
    index.prepare(0);
    index.set(0, std::make_shared<const std::string>("reused"), {original, {}});
    CHECK(index.next() == 2 && index.capture().size() == 551 && after.size() == 550);
    before.each([&](const std::string& key, const Index::Record& record) { CHECK(key != "reused" && record.value == original); });
    index.prepare(0);
    index.erase(0);
    for (std::uint64_t slot = 1; slot < 1100; slot += 2) {
        index.prepare(slot);
        index.erase(slot);
    }
    CHECK(index.capture().size() == 0 && after.size() == 550);
    // After clearing, allocate the lowest free slot regardless of old Views.
    const auto slot = index.next();
    index.prepare(slot);
    index.set(slot, std::make_shared<const std::string>("reborn"), {original, {}});
    CHECK(index.capture().size() == 1 && before.size() == 1100);

    // Index destruction preserves View-owned pages without borrowing original Key/Value storage.
    Index::View retained;
    {
        Index temporary;
        temporary.prepare(0);
        temporary.set(0, std::make_shared<const std::string>("retained"), {changed, {}});
        retained = temporary.capture();
    }
    CHECK(retained.size() == 1);
    retained.each([&](const std::string& key, const Index::Record& record) { CHECK(key == "retained" && record.value == changed); });
}

/// Contraction preserves uncommitted prepared paths and cannot promote a nonzero child as child zero.
void testSnapshotIndexPreparedPaths() {

    Index index;
    // Shared immutable payload for prepared-path cases; payload bytes do not identify slots.
    const auto value = std::make_shared<const Store::Buffer>(Store::Buffer{1});
    // Shared low-slot Key for contraction/reinsertion immutability checks.
    const auto lowKey = std::make_shared<const std::string>("low");
    // High-slot Key forces root growth; deleting it must preserve high-bit slot semantics elsewhere.
    const auto highKey = std::make_shared<const std::string>("high");
    // Prepared-before-set slot; unrelated deletion must retain its path.
    const auto pendingKey = std::make_shared<const std::string>("pending");
    index.prepare(0);
    index.set(0, lowKey, {value, {}});
    index.prepare(64);
    index.set(64, highKey, {value, {}});
    // Pins prechange Keys, payloads, and live count.
    const auto before = index.capture();

    // Slot 1024 has an empty prepared path; deleting 64 must retain it so later set needs no prepare or page allocation.
    index.prepare(1024);
    index.prepare(64);
    index.erase(64);
    index.set(1024, pendingKey, {value, {}});
    CHECK(index.capture().size() == 2 && index.next() == 1);
    before.each([&](const std::string& key, const Index::Record& record) { CHECK((key == "low" || key == "high") && record.value == value); });

    // Sole remaining child is at nonzero position; original slot 1024 must still locate the same record.
    index.prepare(0);
    index.erase(0);
    CHECK(index.next() == 0);
    index.prepare(1024);
    index.set(1024, {}, {value, Clock::Time{} + 1s});
    index.capture().each([&](const std::string& key, const Index::Record& record) { CHECK(key == "pending" && record.deadline == Clock::Time{} + 1s); });

    // Store expiry prepares every path before deleting; intermediate contraction must not require another prepare during commit.
    index.prepare(0);
    index.set(0, lowKey, {value, {}});
    index.prepare(0);
    index.prepare(1024);
    index.erase(1024);
    index.erase(0);
    CHECK(index.capture().size() == 0 && index.next() == 0 && before.size() == 2);

    // Pagination skips sparse high trees by live rank, not numeric slot; reader pause leaves current row unconsumed.
    index.prepare(1);
    index.set(1, lowKey, {value, {}});
    index.prepare(std::uint64_t{1} << 62);
    index.set(std::uint64_t{1} << 62, highKey, {value, {}});
    const auto sparse = index.capture(); // Independent retained root at fixed depth 15.
    CHECK(sparse.page(1, 1, [&](const std::string& key, const Index::Record& record) { CHECK(key == "high" && record.value == value); return true; }) == 1);
    CHECK(sparse.page(0, 1, [&](const std::string& key, const Index::Record&) { CHECK(key == "low"); return false; }) == 0);
    index.prepare(std::uint64_t{1} << 62);
    index.erase(std::uint64_t{1} << 62);
    CHECK(sparse.page(1, 1, [&](const std::string& key, const Index::Record&) { CHECK(key == "high"); return true; }) == 1);
    CHECK(index.capture().page(1, 1, [](const auto&, const auto&) { return false; }) == 0);
}

/// Enumerate every subset of eight sparse slots and compare pagination with independent ordered rows.
void testSnapshotPages() {

    using Rows = std::vector<std::pair<std::string, std::uint8_t>>;                                                 // Literal key/value rows, independent of pages and subtree counts.
    constexpr std::array<std::uint64_t, 8> slots{0, 1, 63, 64, 1023, 1024, std::uint64_t{1} << 62, UINT64_MAX - 1}; // Leaf, branch and full-width boundaries.
    const auto inspect = [](const Index::View& view, const Rows& expected) {
        CHECK(view.size() == expected.size());
        Rows entire; // The full traversal is checked independently of pagination.
        view.each([&](const auto& key, const auto& record) {
            CHECK(record.value && record.value->size() == 1 && !record.deadline);
            entire.emplace_back(key, record.value->front());
        });
        CHECK(entire == expected);
        std::size_t calls = 0; // Invalid positions must reject before invoking user code, even with a zero maximum.
        for (const auto maximum : {std::size_t{0}, std::size_t{1}}) {
            bool rejected = false;
            try {
                view.page(expected.size() + 1, maximum, [&](const auto&, const auto&) { ++calls; return true; });
            } catch (const std::out_of_range&) {
                rejected = true;
            }
            CHECK(rejected && calls == 0);
        }
        for (std::size_t offset = 0; offset <= expected.size(); ++offset) {
            for (const auto maximum : {std::size_t{0}, std::size_t{1}, std::size_t{2}, expected.size(), expected.size() + 1, std::numeric_limits<std::size_t>::max()}) {
                Rows actual; // Expected slices come from the independent sequence rather than production cursor arithmetic.
                const auto count = std::min(maximum, expected.size() - offset);
                Rows slice;
                for (std::size_t position = 0; position < count; ++position) {
                    slice.push_back(expected[offset + position]);
                }
                const auto consumed = view.page(offset, maximum, [&](const auto& key, const auto& record) {
                    CHECK(record.value && record.value->size() == 1 && !record.deadline);
                    actual.emplace_back(key, record.value->front());
                    return true;
                });
                CHECK(consumed == count && actual == slice);
            }
            for (std::size_t stop = 0; stop <= expected.size() - offset; ++stop) {
                calls = 0;
                const auto consumed = view.page(offset, std::numeric_limits<std::size_t>::max(), [&](const auto& key, const auto& record) {
                    CHECK(record.value && record.value->size() == 1);
                    CHECK(expected.at(offset + calls) == std::make_pair(key, record.value->front()));
                    return calls++ != stop;
                });
                CHECK(consumed == stop && calls == std::min(stop + 1, expected.size() - offset));
            }
            for (std::size_t position = 0; position < expected.size() - offset; ++position) {
                /// Distinguish the deliberate callback exception from a failing test assertion.
                struct Pause {};
                calls = 0;
                bool propagated = false; // The same immutable view must remain readable after callback failure.
                try {
                    view.page(offset, std::numeric_limits<std::size_t>::max(), [&](const auto& key, const auto& record) {
                        CHECK(record.value && record.value->size() == 1);
                        CHECK(expected.at(offset + calls) == std::make_pair(key, record.value->front()));
                        if (calls++ == position) {
                            throw Pause{};
                        }
                        return true;
                    });
                } catch (const Pause&) {
                    propagated = true;
                }
                CHECK(propagated && calls == position + 1);
            }
        }
    };

    for (unsigned mask = 0; mask < 256; ++mask) {
        Index index; // Each occupancy subset starts from a fresh tree without retained state from other cases.
        Rows expected;
        std::vector<std::uint64_t> present; // Linear slot membership supplies an independent lowest-free oracle.
        index.prepare(slots.back());
        inspect(index.capture(), expected); // Uncommitted empty paths must not create visible rows or consume rank.
        for (unsigned bit = 0; bit < slots.size(); ++bit) {
            if ((mask & (1U << bit)) == 0) {
                continue;
            }
            const auto slot = slots[bit];
            const auto key = std::to_string(slot);
            const auto value = static_cast<std::uint8_t>(bit + 1);
            index.prepare(slot);
            index.set(slot, std::make_shared<const std::string>(key), {std::make_shared<const Store::Buffer>(Store::Buffer{value}), {}});
            expected.emplace_back(key, value);
            present.push_back(slot);
        }
        std::uint64_t vacancy = 0;
        while (std::ranges::find(present, vacancy) != present.end()) {
            ++vacancy;
        }
        CHECK(index.next() == vacancy);
        for (const auto slot : slots) {
            const auto found = index.find(slot);
            CHECK(static_cast<bool>(found.first) == (std::ranges::find(present, slot) != present.end()));
            CHECK(static_cast<bool>(found.first) == static_cast<bool>(found.second));
        }
        CHECK(!index.at(UINT64_MAX));        // The reserved sentinel was never submitted as a record slot.
        const auto before = index.capture(); // Retain the first immutable generation across replacement and complete removal.
        inspect(before, expected);
        Rows replaced = expected;
        for (std::size_t position = 0; position < present.size(); ++position) {
            index.prepare(present[position]);
            ++replaced[position].second;
            index.set(present[position], {}, {std::make_shared<const Store::Buffer>(Store::Buffer{replaced[position].second}), {}});
        }
        const auto after = index.capture();
        inspect(after, replaced);
        for (const auto slot : present) {
            index.prepare(slot);
            index.erase(slot);
        }
        CHECK(index.next() == 0);
        inspect(index.capture(), {});
        inspect(before, expected);
        inspect(after, replaced);
    }
    std::cout << "PAGES-MODEL subsets=256 slots=8 pruning=0\n";
}

} // namespace

/// Release assertions remain active; exceptions fail CTest explicitly.
int main() {

    try {
        testPutAndRemove();
        testEvictExpired();
        testExtractSinceAndHistoryTrim();
        testBatchesAndRecreation();
        testLongHistorySuffix();
        testExtractBudget();
        testResultLifetime();
        testConcurrentSnapshots();
        testRetentionAndIdleMaintenance();
        testInvalidatedSnapshotRelease();
        testSnapshotIndex();
        testSnapshotIndexPreparedPaths();
        testSnapshotPages();
        std::cout << "All tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        // First failure reason and nonzero status for CTest.
        std::cerr << "Test failed: " << error.what() << '\n';
        return 1;
    }
}
