// Internal KV synchronization store with locked atomic commits, history, expiry, and immutable snapshots.
#pragma once
#include "snapshot_index.hpp"
#include "wheel.hpp"
#include <astra/clock.hpp>
#include <astra/types.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace astra {

/// Internal storage utility without business authentication, Catalog CAS, persistence, or network subscriptions.
/// Each Store owns a version space; one lock protects state/history/snapshots and invokes no caller callbacks.
class Store {
public:
    /// Four-level, ten-bit-per-level timer: 1024 slots per level and 40-bit span, about 348 years at the default 10 ms tick.
    /// Lowest level covers 10.24 s at default precision without cascading.
    using Timer = Wheel<4, 10>;
    /// Buffer owns submitted bytes; Value shares immutable payload among state, history, and snapshots.
    using Buffer = Index::Buffer;
    using Value = Index::Value;

    /// One Key change in this Store's commit sequence, independent of Catalog publisher versions.
    struct Delta {
        /// Owned complete Key; extracted records outlive history trimming.
        std::string key;

        /// Shared immutable write payload, null for Delete; Key/container copies do not copy payload bytes.
        Value value;

        /// True for Delete; a valid empty payload has non-null Value and deleted false.
        bool deleted{};

        /// Local atomic-batch commit sequence, equal across batch Keys; not Catalog business version.
        std::uint64_t version{};

        /// Sole absolute Unix deadline; empty for permanent values and Delete.
        std::optional<Clock::Time> deadline{};
    };

    /// Complete extraction result: stale requires a full snapshot and has no deltas; otherwise all changes through version are present.
    struct Extraction {
        /// True for insufficient history or a future cursor; empty deltas must not be mistaken for synchronization.
        bool stale{};

        /// Last complete commit at lock acquisition; acknowledge only after applying every delta.
        std::uint64_t version{};

        /// Complete batches in commit order; Key order within an expiry batch is unspecified without weakening atomicity.
        std::vector<Delta> deltas;
    };

    /// Version and paged view captured together; map/Key copying occurs outside the state lock while Values share ownership.
    struct Snapshot {
        /// Local commit sequence captured consistently with data.
        std::uint64_t version{};

        /// Owned map of currently live Keys, isolated from later writes.
        std::unordered_map<std::string, Index::Record> data;
    };

    /// capacity counts retained batches (default 1000); retention uses local monotonic time (default 10 min). Zero for either retains no delta history.
    /// interval is strictly positive nanoseconds, default 10 ms; zero or negative throws invalid_argument.
    /// Optional nonnegative Unix initial time supports recovery/tests; default waits for first tick instead of catching up from 1970.
    explicit Store(std::size_t capacity = 1000, Steady::duration retention = std::chrono::minutes(10), std::chrono::nanoseconds interval = std::chrono::milliseconds(10), std::optional<Clock::Time> initial = {}) : capacity_(capacity), retention_(retention), interval_(interval), clock_(initial) {

        if (interval_ <= std::chrono::nanoseconds::zero() || retention_ < Steady::duration::zero() || (initial && initial->time_since_epoch().count() < 0)) {
            throw std::invalid_argument("Invalid Store timing configuration");
        }
    }

    /// Takes value ownership and atomically commits value, history, and the sole absolute deadline; empty deadline means permanent.
    /// Finite deadlines require nonnegative time and tick-initialized Store; caller checks local clock eligibility with Clock::Reading::deadlineAfter.
    /// Allocation failure or version exhaustion commits nothing partially; put neither deletes expired values nor updates time implicitly.
    void put(const std::string& key, Buffer value, std::optional<Clock::Time> deadline = {});

    /// Atomically removes key and records one Delete; absent or already-deleted Keys neither change state nor advance version.
    /// Allocation failure or version exhaustion throws while preserving state and version.
    void remove(const std::string& key);

    /// Catches up complete ticks through nonnegative Unix now and deletes expired entries atomically; ceil to tick boundaries delays less than one tick, never expires early.
    /// Repeated or backward valid times do not advance; empty deadlines never expire.
    /// local controls history retention only, separate from business time; injectable for tests and absent from Entry/Delta.
    /// Allocation failure or version exhaustion propagates with data/history/version unchanged; detached nodes retry on the next tick.
    /// Catch-up includes empty ticks, without O(1) or fixed-latency guarantees.
    /// After history cleanup, maps empty above 4096 buckets swap to an empty table and free buckets outside the lock; nonempty maps do not shrink automatically.
    void tick(Clock::Time now, Steady::time_point local = Steady::now());

    /// Returns this instance's complete version under lock without allocation; says nothing about other instances' synchronization.
    std::uint64_t version() const;

    /// Captures a consistent view under a short lock, copies Key/map outside it, reuses same-version cache, and permits one builder at a time.
    /// Writes continue during construction; returns a captured version without endless catch-up or caching old results as new.
    /// Allocation failure publishes no partial snapshot; previously returned immutable snapshots survive later commits.
    std::shared_ptr<const Store::Snapshot> snapshot();

    /// Returns complete deltas after since, or explicitly requests a snapshot for insufficient history/future cursors.
    /// Caller must first check instance and subscription range; supports same-instance whole-range history only.
    /// maxBytes bounds copied Delta arrays and Key bytes including terminators; default 32 MiB, zero permits empty results only.
    /// Excludes shared Value payload and allocator overhead; not an RSS or encoding cap. Local callers choose it without trusting remote input directly.
    /// Budget overflow throws length_error before copying; allocation may throw bad_alloc. Store stays unchanged, without batch truncation or a larger snapshot fallback.
    /// Transport adapters catch resource exceptions and map status; Store has no gRPC dependency. Do not acknowledge before receiving all results.
    Store::Extraction extract(std::uint64_t since, std::size_t maxBytes = 32U * 1024 * 1024) const;

private:
    /// Mutable map node; null value caches a deleted Key for reuse without a separate deleted flag.
    /// History retains Delete continuation; node version prevents old-history retirement from reclaiming a newer cached deletion.
    struct Entry : public Timer::Node {
        /// Borrows its unordered_map Key; rehash preserves address and erase cancels the timer first.
        const std::string* key{nullptr};
        /// Live record's read-only index slot; invalid after deletion and reacquired on rebuild, with timer-node address unchanged.
        std::uint64_t snapshotSlot{};
        /// Null denotes a deleted node reusable by the same Key before history retirement.
        Value value;
        /// Last write/delete commit, preventing old history from reclaiming a reused node.
        std::uint64_t version{};
        /// Sole finite deadline; segmented long-lease wakeups never change it.
        std::optional<Clock::Time> deadline{};
    };

    /// Complete atomic history batch, possibly multiple expiry Keys; retain and trim only as a whole.
    struct Batch {
        /// Local commit sequence exactly one above its predecessor; failures/no-ops create no batch.
        std::uint64_t version;
        /// Local monotonic batch timestamp for age-based retention.
        Steady::time_point timestamp;
        /// Complete immutable post-publication commit records; expiry may include several.
        std::vector<Store::Delta> records;
    };

    /// Requires mutex_; computes next sequence without mutation and throws overflow_error on exhaustion.
    std::uint64_t advance() const;
    /// Requires state lock; schedules a finite deadline from the advanced boundary without allocation or exceptions.
    void schedule(Entry& entry, Clock::Time boundary) noexcept;

    /// After verifying later >= earlier, returns unsigned clock-count difference without signed-extreme subtraction overflow.
    static std::uint64_t distance(Steady::time_point later, Steady::time_point earlier) noexcept;

    /// Requires mutex_; trims complete history and eligible empty nodes, advancing continuation floor without allocation.
    void trim(Steady::time_point now);

    /// Reads captured View only, without mutable map or state-lock access; allocation failure affects no published state.
    static std::shared_ptr<const Store::Snapshot> dump(const Index::View& view, std::uint64_t version);

    /// Sole state lock; mutable lets read queries share writers' synchronization boundary.
    mutable std::mutex mutex_;
    /// Serializes snapshot builders only; writes/TTL never acquire it. If both are held, acquire snapshotMutex_ before mutex_.
    std::mutex snapshotMutex_;
    /// Mutable scheduling state is separate from immutable views; index changes and version publish in one nonthrowing commit.
    Index snapshotIndex_;

    /// Current Key index and short-lived empty-node cache for same-Key reuse; snapshots omit empty nodes.
    std::unordered_map<std::string, Entry> entries_;

    /// Last complete local sequence, initially zero; uint64_t exhaustion rejects new commits.
    std::uint64_t version_{};

    /// Fixed retained-batch capacity, neither record count nor byte limit.
    std::size_t capacity_;

    /// Maximum monotonic age of retained history batches.
    Steady::duration retention_;
    /// Positive nanosecond tick interval, validated once at construction and fixed afterward.
    const std::chrono::nanoseconds interval_;
    /// Tracks wheel_.now() so exceptions do not repeat completed ticks.
    std::optional<Clock::Time> clock_;
    /// wheel_ is destroyed before entries_ and detaches every hook; later node destructors may cancel safely again.
    Timer wheel_{};

    /// Complete batches in increasing commit order; deque supports front trimming and binary search.
    std::deque<Batch> history_;

    /// Last trimmed complete version; callers at this version may still resume from the next delta.
    std::uint64_t oldest_{};

    /// Caches only a complete snapshot matching current version; commit transfers old cache for release outside the state lock.
    std::shared_ptr<const Store::Snapshot> cache_;
};

} // namespace astra
