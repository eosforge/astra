// Internal memory KV storage with atomic history, expiry, snapshots, and incremental extraction.
#include "store.hpp"

#include <algorithm>
#include <limits>
#include <ranges>
#include <stdexcept>

namespace astra {

/// Atomically inserts or replaces a value and appends its change history.
void Store::put(const std::string& key, Buffer value, std::optional<Clock::Time> deadline) {

    if (deadline && deadline->time_since_epoch().count() < 0) {
        throw std::invalid_argument("Store deadline must be nonnegative Unix time");
    }

    // Take payload ownership and prepare Key/container allocations outside the lock before committing the unique record.

    auto shared = std::make_shared<const Buffer>(std::move(value));

    // Commit sequence is not assigned yet; zero exists only in unpublished temporary records.
    std::vector<Store::Delta> records;

    records.emplace_back(key, shared, false, 0, deadline);

    // Takes the old cache and is declared before lock so final snapshot release occurs after unlocking.
    std::shared_ptr<const Snapshot> retired;
    // Serializes map, history, and version with exception-safe unlock.
    std::lock_guard lock(mutex_);

    if (deadline && !clock_) {
        throw std::logic_error("Store requires an epoch anchor before finite deadlines");
    }

    // One local monotonic timestamp for this batch's history, separate from business Unix deadlines.
    const auto now = Steady::now();

    // Compute without publishing the next version; reject exhaustion before any wrap or state mutation.
    const auto version = advance();
    records.front().version = version;

    // it points to existing or inserted entry; inserted controls rollback of an unfinished new Key.
    auto [it, inserted] = entries_.try_emplace(key);

    // Lock hides temporary insertion; allocation failure removes only this new entry and preserves existing contents.
    std::uint64_t snapshotSlot{};
    // Initially empty; owns a Key copy only for a newly occupied slot, while replacement reuses the old Key.
    Index::Key snapshotKey;
    try {
        // Mutable Entry stays in the map; prepare private read-only-index paths and reuse existing shared Key text on replacement.
        snapshotSlot = it->second.value ? it->second.snapshotSlot : snapshotIndex_.next();
        if (!it->second.value) {
            snapshotKey = std::make_shared<const std::string>(key);
        }
        snapshotIndex_.prepare(snapshotSlot);

        history_.push_back({version, now, std::move(records)});
    } catch (...) {

        if (inserted) {
            entries_.erase(it);
        }
        throw;
    }

    // History is prepared; remaining assignments allocate nothing and readers observe complete state before or after commit.
    snapshotIndex_.set(snapshotSlot, std::move(snapshotKey), {shared, deadline});
    it->second.snapshotSlot = snapshotSlot;
    it->second.key = &it->first;
    it->second.value = std::move(shared);
    it->second.version = version;
    it->second.deadline = deadline;

    // Schedule absolute expiry from the advanced tick boundary without adding event-loop delay to the lease.
    if (clock_) {
        schedule(it->second, *clock_);
    }

    version_ = version;
    trim(now);
    retired = std::move(cache_);
}

/// Commits deletion and releases payload while retaining the empty map node temporarily for reuse.
void Store::remove(const std::string& key) {

    std::shared_ptr<const Snapshot> retired;
    // One lock covers existence check and delete commit without unlock/relookup.
    std::lock_guard lock(mutex_);

    const auto now = Steady::now();

    // Current map entry; absent or empty value is a no-op without a separate deleted flag.
    auto it = entries_.find(key);
    if (it == entries_.end() || !it->second.value) {
        return;
    }

    // Version is unpublished until history append succeeds.
    const auto version = advance();
    // Owns the Delete record; node version is retained only to match reclamation of cached empty entries.
    std::vector<Store::Delta> records;

    records.emplace_back(key, nullptr, true, version);
    snapshotIndex_.prepare(it->second.snapshotSlot);
    history_.push_back({version, now, std::move(records)});

    snapshotIndex_.erase(it->second.snapshotSlot);
    Timer::cancel(it->second);
    it->second.value = nullptr;
    it->second.version = version;
    it->second.deadline.reset();
    version_ = version;
    trim(now);
    retired = std::move(cache_);
}

/// Catch up ticks and prepare complete history under one lock; preparation detaches scheduling hooks without changing visible state or version.
void Store::tick(Clock::Time now, Steady::time_point local) {

    if (now.time_since_epoch().count() < 0) {
        throw std::invalid_argument("Store time must be nonnegative Unix time");
    }

    std::shared_ptr<const Snapshot> retired;
    // Takes only fully emptied large bucket arrays; declared before lock for bulk reclamation outside the state critical section.
    decltype(entries_) retiredEntries;
    static_assert(noexcept(entries_.swap(retiredEntries)), "Empty Store reclamation must not throw after commit");
    // Protects one coherent entry/version/history state; this operation invokes no external callbacks.
    std::lock_guard lock(mutex_);
    // First valid Unix time sets the tick anchor directly; finite leases were not yet allowed, so no scan or epoch-zero catch-up is needed.
    if (!clock_) {
        clock_ = now;
    }

    // Nonnegative complete ticks to catch up; no truncation, with sub-tick remainder retained in anchor difference.
    const auto pending = now > *clock_ ? static_cast<std::uint64_t>((now - *clock_) / interval_) : 0;

    // Holds commit records and Keys requiring rescheduling on failure; empty ticks preallocate no array.
    std::vector<Store::Delta> records;
    try {
        for (std::uint64_t step = 0; step < pending; ++step) {
            // Distinguishes callbacks left by an earlier exception from this advancement; actual tick boundaries may differ.
            const auto before = wheel_.now();
            try {
                wheel_.tick([&](Timer::Node* node) {
                    // Entry address is stable under the state lock; compare actual deadline so segmented wakeups do not expire values early.
                    auto& entry = *static_cast<Entry*>(node);
                    // Actual tick boundary for this callback, including work left by a prior exception.
                    const auto boundary = *clock_ + (wheel_.now() == before ? std::chrono::nanoseconds::zero() : interval_);
                    if (entry.deadline && *entry.deadline > boundary) {
                        schedule(entry, boundary);
                        return;
                    }
                    try {
                        records.emplace_back(*entry.key, nullptr, true, 0);
                    } catch (...) {
                        // Current node is not in records yet; reschedule separately so valid data retains its future expiration opportunity.
                        schedule(entry, boundary);
                        throw;
                    }

                    // Page allocation is preparation; this node is already in records, so outer failure handling reschedules it.
                    snapshotIndex_.prepare(entry.snapshotSlot);
                });
            } catch (...) {
                // Wheel may advance before callback failure; retain its logical boundary without counting the tick twice.
                if (wheel_.now() != before) {
                    *clock_ += interval_;
                }
                throw;
            }
            *clock_ += interval_;
        }
        if (!records.empty()) {
            // Compute version without publication; allocate the empty history batch before nonthrowing record swap.
            const auto version = advance();
            for (auto& record : records) {
                record.version = version;
            }
            history_.emplace_back(version, local, std::vector<Store::Delta>{});
        }
    } catch (...) {
        // Collected nodes remain in map; rescheduling allocates nothing and does not scan unexpired entries.
        for (const auto& record : records) {
            schedule(entries_.find(record.key)->second, *clock_);
        }
        throw;
    }

    if (!records.empty()) {
        // Allocation-free commit starts here; all catch-up expiry forms one version, not per-Key or per-tick publications.
        history_.back().records.swap(records);
        // Prepared whole-batch delete sequence shared by all expired entries.
        const auto version = history_.back().version;
        for (const auto& record : history_.back().records) {
            // Preparation retained map entries, so each lookup must succeed.
            auto& entry = entries_.find(record.key)->second;
            snapshotIndex_.erase(entry.snapshotSlot);
            Timer::cancel(entry);
            entry.value.reset();
            entry.version = version;
            entry.deadline.reset();
        }
        version_ = version;
        retired = std::move(cache_);
    }

    // Empty ticks also trim tombstones; return buckets only when the map has no nodes, not merely no live values.
    trim(local);
    // Keep small-table capacity to avoid churn; 4096 buckets is an internal reclamation threshold, not a Key or protocol limit.
    // Never rehash nonempty maps, scan/move scheduled nodes, or introduce allocation failure after commit.
    if (entries_.empty() && entries_.bucket_count() > 4096) {
        entries_.swap(retiredEntries);
    }
}

/// After checking order, unsigned subtraction covers the full distance between finite time_point extremes.
std::uint64_t Store::distance(Steady::time_point later, Steady::time_point earlier) noexcept {
    static_assert(std::numeric_limits<Steady::duration::rep>::digits <= 63);
    return static_cast<std::uint64_t>(later.time_since_epoch().count()) - static_cast<std::uint64_t>(earlier.time_since_epoch().count());
}

/// Retain the absolute finite deadline; leases beyond one Wheel span use segmented wakeups that recheck and reschedule.
void Store::schedule(Entry& entry, Clock::Time boundary) noexcept {

    if (!entry.deadline) {
        Timer::cancel(entry);
        return;
    }

    // Representable remaining duration between nonnegative business times; expired records keep zero delay.
    const auto remaining = *entry.deadline > boundary ? *entry.deadline - boundary : std::chrono::nanoseconds::zero();
    // interval_ is positive; ceil remaining/interval with quotient and remainder, avoiding prior multiplication before unsigned tick conversion.
    const auto delay = static_cast<std::uint64_t>(remaining / interval_ + (remaining % interval_ != std::chrono::nanoseconds::zero()));
    // Clamped delay is schedulable; Wheel places zero on the next tick, never invokes callbacks inside put.
    static_cast<void>(wheel_.schedule(entry, std::min(delay, Timer::limit)));
}

/// Returns this Store's last complete commit sequence under lock.
std::uint64_t Store::version() const {

    // Same state lock observes complete commits without a separate atomic version boundary.
    std::lock_guard lock(mutex_);
    return version_;
}

/// Returns a complete immutable full snapshot at a captured version.
std::shared_ptr<const Store::Snapshot> Store::snapshot() {

    {

        std::lock_guard lock(mutex_);
        if (cache_) {
            return cache_;
        }
    }

    // Only snapshot builders wait on this lock; writes and TTL never wait for full-table copying.
    std::lock_guard builder(snapshotMutex_);
    // Owns the captured root; release pages only after read-completion synchronization.
    Index::View view;
    // Version captured with view under one state lock; initial zero is an uncaptured sentinel.
    std::uint64_t version{};
    {

        std::lock_guard lock(mutex_);
        if (cache_) {
            return cache_;
        }
        view = snapshotIndex_.capture();
        version = version_;
    }

    // O(N) container allocation, Key copying, and view reclamation occur outside the state lock; later writers copy only shared modified paths.
    std::shared_ptr<const Snapshot> result;
    try {
        result = dump(view, version);
    } catch (...) {
        // Exceptional exits also finish reads, synchronize through the state lock, then release View outside it; shared_ptr exclusivity alone is insufficient.
        std::lock_guard lock(mutex_);
        throw;
    }
    {
        // Synchronize read completion with writers before View destruction so later exclusive in-place page writes cannot overlap old reads.
        std::lock_guard lock(mutex_);
        if (version_ == version) {
            cache_ = result;
        }
    }
    return result;
}

/// Builds an owned Key index from live captured contents only.
std::shared_ptr<const Store::Snapshot> Store::dump(const Index::View& view, std::uint64_t version) {

    // Writable only inside this function, then returned as shared_ptr<const Store::Snapshot>.
    auto snapshot = std::make_shared<Store::Snapshot>();
    snapshot->version = version;
    // Reserve live entries only; tombstones and deleted slot numbers do not grow buckets.
    snapshot->data.reserve(view.size());
    view.each([&](const std::string& key, const Index::Record& record) { snapshot->data.emplace(key, record); });
    return snapshot;
}

/// Extracts complete history after the caller's cursor, or requests a full snapshot.
Store::Extraction Store::extract(std::uint64_t since, std::size_t maxBytes) const {

    // Lock prevents concurrent history trimming during range lookup, sizing, and record copying.
    std::lock_guard lock(mutex_);
    // Accumulates a temporary result; allocation failure changes neither Store nor earlier caller-owned results.
    // Future cursors or insufficient retained history return stale, requiring a full snapshot.
    Store::Extraction result{.stale = since > version_ || since < oldest_, .version = version_, .deltas = {}};

    if (result.stale || since == version_) {
        return result;
    }

    // First later batch found by version binary search, without scanning acknowledged prefixes.

    const auto first = std::ranges::upper_bound(history_, since, {}, &Batch::version);
    // Borrows a stable locked suffix without allocating containers or extra state.
    const auto batches = std::ranges::subrange(first, history_.end());

    // Counts deltas for one array reservation; Key copies still allocate, so this is not allocation-free.
    std::size_t totalDeltas = 0;
    // Subtract array cost before strings; subtraction/division checks avoid accounting overflow.
    auto remaining = maxBytes;
    for (const auto& batch : batches) {
        // Batch is an indivisible commit; check remaining capacity before sums or vector-limit overflow.
        if (batch.records.size() > result.deltas.max_size() - totalDeltas || batch.records.size() > remaining / sizeof(Delta)) {
            throw std::length_error("Store delta copy budget exceeded");
        }
        remaining -= batch.records.size() * sizeof(Delta);
        // Keys may allocate separately from shared Values; charge even inline strings conservatively without assuming standard-library layout.
        for (const auto& record : batch.records) {
            if (record.key.size() >= remaining) {
                throw std::length_error("Store delta copy budget exceeded");
            }
            remaining -= record.key.size() + 1;
        }
        totalDeltas += batch.records.size();
    }

    result.deltas.reserve(totalDeltas);

    // Append the measured iterator range into reserved storage; Values retain shared immutable payloads.
    for (const auto& batch : batches) {
        result.deltas.insert(result.deltas.end(), batch.records.begin(), batch.records.end());
    }

    // Version is the complete result's commit barrier; caller must apply every record before acknowledging it.
    return result;
}

/// Computes the next monotonic version without publishing it.
std::uint64_t Store::advance() const {

    if (version_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("Store version exhausted");
    }
    return version_ + 1;
}

/// Trims complete history by capacity/age and reclaims eligible empty nodes.
void Store::trim(Steady::time_point now) {

    // History owns Delete continuation; match versions before reclaiming nodes so delete/recreate cycles cannot release newer cached entries.
    while (!history_.empty() && (history_.size() > capacity_ || retention_ == Steady::duration::zero() || (now >= history_.front().timestamp && distance(now, history_.front().timestamp) >= static_cast<std::uint64_t>(retention_.count())))) {
        // Borrows a retiring batch; inspect Deletes only, without relooking up every ordinary write.
        for (const auto& record : history_.front().records) {
            if (record.deleted) {
                // Entry may have been recreated or deleted again; reclaim only empty nodes still matching this retiring record.
                const auto entry = entries_.find(record.key);
                if (entry != entries_.end() && !entry->second.value && entry->second.version == record.version) {
                    entries_.erase(entry);
                }
            }
        }

        oldest_ = history_.front().version;

        history_.pop_front();
    }
}

} // namespace astra
