// Own authoritative Almanac versions, consistent views, and atomic state publication.
#include "almanac.hpp"

#include <astra/profile.hpp>

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace astra {
/// Native single-Scope state. Map supports lookup and Index supports shared paging; both share key/value ownership.
struct Almanac::State {

    /// Bind owned key bytes and current payload to one reusable page slot.
    struct Entry {
        /// Owns immutable strings borrowed by Map's string_views, independently of request/Protobuf lifetime.
        std::shared_ptr<const std::string> key;
        /// Current immutable bytes shared with pages/history; a private new node may be empty before commit.
        Value value;
        /// Compact reusable Index slot, not key identity.
        std::uint64_t slot{};
    };

    /// Index immutable owned key strings by borrowed string views; entries retain their key owners.
    std::unordered_map<std::string_view, Entry> entries;
    /// Reuses page copying, not Store's versions, TTLs, or commit semantics; deadline is always absent.
    Index index;
    /// Polaris's fully installed version, never renumbered locally.
    std::uint64_t version{};

    /// Track logical Almanac payload bytes for capacity checks, independently of allocator usage.
    std::size_t bytes{};
};

Almanac::Usage Almanac::usage() const {
    const std::lock_guard lock(*gate_);
    return Usage{state_->bytes, historyBytes_, ready_ ? std::optional(state_->version) : std::nullopt};
}

std::size_t Almanac::Change::bytes() const noexcept {
    return sizeof(Change) + (key ? key->size() : 0) + (value ? value->size() : 0);
}

Almanac::View::Fence::~Fence() {
    // Synchronize read completion on every exit; the lock never spans traversal or user callbacks.
    const std::lock_guard lock(*gate);
}

Almanac::View::View(Index::View root, std::uint64_t version, std::size_t bytes, std::shared_ptr<std::mutex> gate) : root_(std::move(root)), version_(version), size_(root_.size()), bytes_(bytes), gate_(std::move(gate)) {}

std::uint64_t Almanac::View::version() const noexcept {
    return version_;
}

std::size_t Almanac::View::size() const noexcept {
    return size_;
}

std::size_t Almanac::View::bytes() const noexcept {
    return bytes_;
}

Almanac::Draft::Draft(std::uint64_t version, Limits limits) : state_(std::make_unique<State>()), limits_(limits) {
    state_->version = version;
}

Almanac::Draft::~Draft() = default;

Almanac::Draft::Draft(Draft&&) noexcept = default;

Almanac::Draft& Almanac::Draft::operator=(Draft&&) noexcept = default;

std::expected<void, Almanac::Error> Almanac::Draft::set(std::string key, Buffer value) {

    ASTRA_PROFILE_SCOPE("star.almanac.Almanac.Draft.set");

    if (!state_ || !Almanac::valid(key, &value)) {
        return std::unexpected(Error::Input);
    }
    if (state_->version == 0) {
        return std::unexpected(Error::Version);
    }
    if (state_->entries.contains(key)) {
        return std::unexpected(Error::Duplicate);
    }

    const auto bytes = key.size() + value.size();
    if (state_->entries.size() >= limits_.records || bytes > limits_.bytes - state_->bytes) {
        return std::unexpected(Error::Capacity);
    }

    // Prepare owned key/value and a new slot; later failure must remove the temporary Map entry.
    auto name = std::make_shared<const std::string>(std::move(key));
    auto shared = std::make_shared<const Buffer>(std::move(value));
    const auto slot = state_->index.next();

    const auto [entry, inserted] = state_->entries.try_emplace(*name, State::Entry{name, shared, slot});
    if (!inserted) {
        return std::unexpected(Error::Duplicate);
    }
    try {
        state_->index.prepare(slot);
    } catch (...) {
        state_->entries.erase(entry);
        throw;
    }

    // All allocations succeeded; update candidate index and accounting without touching the active Scope.
    state_->index.set(slot, std::move(name), {std::move(shared), {}});
    state_->bytes += bytes;
    return {};
}

Almanac::Almanac() : Almanac(Limits{}) {}

Almanac::Almanac(Limits limits) : limits_(limits), state_(std::make_unique<State>()) {}

Almanac::~Almanac() = default;

Almanac::Draft Almanac::prepare(std::uint64_t version) const {

    ASTRA_PROFILE_SCOPE("star.almanac.Almanac.prepare");
    return Draft(version, limits_);
}

std::expected<bool, Almanac::Error> Almanac::reset(Draft&& draft) {

    ASTRA_PROFILE_SCOPE("star.almanac.Almanac.reset");

    if (!draft.state_) {
        return std::unexpected(Error::Input);
    }
    if (draft.state_->entries.size() > limits_.records || draft.state_->bytes > limits_.bytes) {
        return std::unexpected(Error::Capacity);
    }

    // Construct retired/history before lock so final references are reclaimed after unlock.
    std::unique_ptr<State> retired;
    std::deque<Change> history;
    ASTRA_PROFILE_BEGIN(profileLock130, "star.almanac.Almanac.reset.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock130);
    if (ready_ && draft.state_->version < state_->version) {
        return std::unexpected(Error::Version);
    }
    if (ready_ && draft.state_->version == state_->version) {
        return false;
    }

    // Private preparation is complete. Allocation-free pointer swap publishes data, authoritative version, and the new history boundary together.
    retired = std::move(state_);
    state_ = std::move(draft.state_);
    history.swap(history_);
    historyBytes_ = 0;
    ready_ = true;
    return true;
}

std::expected<bool, Almanac::Error> Almanac::apply(std::uint64_t version, std::string key, std::optional<Buffer> value, std::size_t retention, Change* committed) {

    ASTRA_PROFILE_SCOPE("star.almanac.Almanac.apply");

    if (!valid(key, value ? &*value : nullptr)) {
        return std::unexpected(Error::Input);
    }
    if (version == 0) {
        return std::unexpected(Error::Version);
    }

    // Reuse existing shared keys on overwrite/delete; prepare ownership for new keys before publication.
    Change change{{}, value ? std::make_shared<const Buffer>(std::move(*value)) : nullptr, version};
    // Reclaim large overwritten or evicted bodies outside the business lock.
    std::vector<Change> retired;
    Value previous;
    ASTRA_PROFILE_BEGIN(profileLock162, "star.almanac.Almanac.apply.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock162);
    if (!ready_) {
        return std::unexpected(Error::Unready);
    }
    if (version <= state_->version) {
        return false;
    }
    if (state_->version == std::numeric_limits<std::uint64_t>::max() || version != state_->version + 1) {
        return std::unexpected(Error::Version);
    }

    auto entry = state_->entries.find(key);
    bool inserted = false;

    auto bytes = state_->bytes;
    if (entry != state_->entries.end()) {
        change.key = entry->second.key;
        bytes -= change.key->size() + entry->second.value->size();
    } else {
        change.key = std::make_shared<const std::string>(std::move(key));
    }
    if (change.value) {

        const auto added = change.key->size() + change.value->size();
        if ((entry == state_->entries.end() && state_->entries.size() >= limits_.records) || added > limits_.bytes - bytes) {
            return std::unexpected(Error::Capacity);
        }
        bytes += added;
    }

    // Prepare reclamation only for the history prefix actually being evicted, without copying all history per commit.

    // If the new item alone exceeds budget or history capacity is zero, eviction may include every old item and the new one.
    const auto cost = change.bytes();
    if (cost > std::numeric_limits<std::size_t>::max() - historyBytes_ || history_.size() == std::numeric_limits<std::size_t>::max()) {
        return std::unexpected(Error::Capacity);
    }
    auto retained = history_.size() + 1;
    auto backlog = historyBytes_ + cost;
    std::size_t evicted{};
    while (retained > limits_.history || backlog > std::min(limits_.backlog, retention) || (evicted != 0 && evicted < history_.size() && history_[evicted - 1].version == history_[evicted].version)) {
        backlog -= evicted < history_.size() ? history_[evicted].bytes() : cost;
        ++evicted;
        --retained;
    }
    retired.reserve(evicted);

    // Map/page preparation may fail; history enqueue is the last fallible operation.
    // Page failure leaves only equivalent private pages; catch removes the new Map node.
    if (change.value && entry == state_->entries.end()) {

        const auto slot = state_->index.next();
        const auto result = state_->entries.try_emplace(*change.key, State::Entry{change.key, {}, slot});
        entry = result.first;
        inserted = result.second;
    }
    try {
        if (entry != state_->entries.end()) {
            state_->index.prepare(entry->second.slot);
        }
        // Enqueue before evicting, even if the new item will be evicted. Failure publishes nothing and performs no pop_front.
        history_.push_back(change);
    } catch (...) {
        if (inserted) {
            state_->entries.erase(entry);
        }
        throw;
    }

    // Publication below is allocation-free. Same-value Set and missing-key Delete still publish the authoritative version and full history.
    if (entry != state_->entries.end()) {
        previous = std::move(entry->second.value);
        if (change.value) {
            state_->index.set(entry->second.slot, inserted ? change.key : nullptr, {change.value, {}});
            entry->second.value = change.value;
        } else {
            // Save the slot before erasing the Map entry; do not reuse invalid iterators or key views.
            const auto slot = entry->second.slot;
            state_->entries.erase(entry);
            state_->index.erase(slot);
        }
    }
    state_->bytes = bytes;
    state_->version = version;
    historyBytes_ = backlog;
    if (committed) {
        *committed = change;
    }

    for (std::size_t item = 0; item < evicted; ++item) {
        retired.push_back(std::move(history_.front()));
        history_.pop_front();
    }
    return true;
}

std::expected<bool, Almanac::Error> Almanac::apply(std::uint64_t version, std::vector<Change> changes, std::size_t retention, Change* committed) {

    // Validate the complete batch before touching state, without extra batch count/byte limits.
    std::unordered_set<std::string_view> names;
    if (!version || changes.empty()) {
        return std::unexpected(Error::Input);
    }
    for (auto& change : changes) {
        if (!change.key || change.batch || !valid(*change.key, change.value.get()) || !names.insert(*change.key).second) {
            return std::unexpected(Error::Input);
        }
        change.version = version;
    }

    // Release old roots/history after unlock; allocate notification envelopes before commit.
    Index retired;
    std::vector<Change> discarded;
    auto batch = std::make_shared<std::vector<Change>>(std::move(changes));
    const std::lock_guard lock(*gate_);
    if (!ready_) {
        return std::unexpected(Error::Unready);
    }
    if (version <= state_->version) {
        return false;
    }
    if (state_->version == UINT64_MAX || version != state_->version + 1) {
        return std::unexpected(Error::Version);
    }
    auto bytes = state_->bytes;
    auto records = state_->entries.size();
    for (auto& change : *batch) {
        const auto old = state_->entries.find(*change.key);
        if (old != state_->entries.end()) {
            change.key = old->second.key;
            bytes -= change.key->size() + old->second.value->size();
            --records;
        }
    }
    // Subtract all replaced values before admission so request order cannot reject a valid batch; keep accumulated bytes bounded.
    for (const auto& change : *batch) {
        if (change.value) {
            const auto cost = change.key->size() + change.value->size();
            if (records >= limits_.records || cost > limits_.bytes - bytes) {
                return std::unexpected(Error::Capacity);
            }
            bytes += cost;
            ++records;
        }
    }
    auto backlog = historyBytes_; // Check history count arithmetic before appending.
    for (const auto& change : *batch) {
        const auto cost = change.bytes();
        if (cost > std::numeric_limits<std::size_t>::max() - backlog) {
            return std::unexpected(Error::Capacity);
        }
        backlog += cost;
    }

    // Copy only the page root, with pages copied on write; failure removes both new lookup entries and history tail.
    Index candidate = state_->index;
    std::vector<std::shared_ptr<const std::string>> added;
    added.reserve(batch->size());
    std::size_t queued{};
    try {
        for (const auto& change : *batch) {
            auto entry = state_->entries.find(*change.key); // Hash iterators must not survive the next insertion.
            if (entry == state_->entries.end() && change.value) {
                const auto slot = candidate.next();
                added.push_back(change.key);
                entry = state_->entries.try_emplace(*change.key, State::Entry{change.key, {}, slot}).first;
            }
            if (entry != state_->entries.end()) {
                candidate.prepare(entry->second.slot);
                if (change.value) {
                    candidate.set(entry->second.slot, entry->second.value ? nullptr : change.key, {change.value, {}});
                } else {
                    candidate.erase(entry->second.slot);
                }
            }
            history_.push_back(change);
            ++queued;
        }
        // Evict history by whole versions; retaining only a transaction suffix cannot represent contiguous history.
        std::size_t evicted{};
        while (history_.size() - evicted > limits_.history || backlog > std::min(limits_.backlog, retention)) {
            const auto oldest = history_[evicted].version;
            do {
                backlog -= history_[evicted++].bytes();
            } while (evicted < history_.size() && history_[evicted].version == oldest);
        }
        discarded.reserve(evicted);
        for (std::size_t index = 0; index < evicted; ++index) {
            discarded.push_back(std::move(history_.front()));
            history_.pop_front();
        }
    } catch (...) {
        while (queued > 0) {
            history_.pop_back();
            --queued;
        }
        for (const auto& key : added) {
            state_->entries.erase(*key);
        }
        throw;
    }

    // No further allocation. Retired roots/views keep old values alive while version and complete index publish together.
    retired = std::move(state_->index);
    state_->index = std::move(candidate);
    for (const auto& change : *batch) {
        if (change.value) {
            state_->entries.find(*change.key)->second.value = change.value;
        } else {
            state_->entries.erase(*change.key);
        }
    }
    state_->bytes = bytes;
    state_->version = version;
    historyBytes_ = backlog;
    if (committed) {
        *committed = Change{{}, {}, version, std::move(batch)};
    }
    return true;
}

std::expected<Almanac::View, Almanac::Error> Almanac::view() const {

    const std::lock_guard lock(*gate_);
    if (!ready_) {
        return std::unexpected(Error::Unready);
    }
    return View(state_->index.capture(), state_->version, state_->bytes, gate_);
}

std::expected<Almanac::Point, Almanac::Error> Almanac::find(std::string_view key) const {

    if (!valid(key, nullptr)) {
        return std::unexpected(Error::Input);
    }
    const std::lock_guard lock(*gate_);
    if (!ready_) {
        return std::unexpected(Error::Unready);
    }

    const auto found = state_->entries.find(key);
    return Point{state_->version, found == state_->entries.end() ? nullptr : found->second.value};
}

std::expected<Almanac::Replay, Almanac::Error> Almanac::replay(std::uint64_t since) const {

    ASTRA_PROFILE_SCOPE("star.almanac.Almanac.replay");

    ASTRA_PROFILE_BEGIN(profileLock284, "star.almanac.Almanac.replay.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock284);
    if (!ready_) {
        return std::unexpected(Error::Unready);
    }
    if (since > state_->version) {
        return std::unexpected(Error::Version);
    }
    if (since == state_->version) {
        return Replay{state_->version, {}};
    }
    if (history_.empty() || since < history_.front().version - 1) {
        return std::unexpected(Error::History);
    }

    // Binary-search deque versions, copying only budgeted metadata and shared references.
    const auto begin = std::ranges::upper_bound(history_, since, {}, &Change::version);
    return Replay{state_->version, {begin, history_.end()}};
}

bool Almanac::valid(std::string_view key, const Buffer* value) noexcept {
    return !key.empty() && key.size() <= 1024 && key.find('\0') == std::string_view::npos && (!value || value->size() <= 1024 * 1024);
}
} // namespace astra
