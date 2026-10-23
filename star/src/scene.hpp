// Maintain scoped projected views and replay history with atomic staged publication.
#pragma once
#include "pages.hpp"
#include <astra/profile.hpp>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace astra {
/// Single-Scope public projection without version rules, deadlines, or source positions. Item contains no hidden TTL/orders.
/// Name shares Origin address/key without copying keys/payloads. Writes/Edit lifetime require exclusive domain gate; const reads require shared access.
/// Two-phase commit requires noexcept Item copy construction/move assignment, enforced at template use.
template <typename Item, typename Name>
requires(std::is_nothrow_copy_constructible_v<Item> && std::is_nothrow_move_assignable_v<Item>)
class Scene {
public:
    /// Public-content page root; renewal never touches this tree.
    using Tree = Pages<Item, Name>;
    /// Shared immutable Name; moving Event transfers ownership without moving Name or its SSO string.
    using Key = typename Tree::Key;
    /// Bounded allocation-free payload measure; metadata is charged separately.
    using Measure = std::size_t (*)(const Item&) noexcept;

    /// Conservative per-Scope content/history limits; caller also bounds active Scopes and total recovery workspace.
    struct Limits {
        /// Visible records; zero permits only an empty Scope.
        std::size_t records = 65536;
        /// Logical current content/index bytes, not RSS.
        std::size_t bytes = 64 * 1024 * 1024;
        /// Contiguous visible changes; zero disables old-cursor recovery.
        std::size_t history = 4096;
        /// Logical history bytes, conservatively including shared payload references.
        std::size_t backlog = 8 * 1024 * 1024;
        /// History age pruned on writes; zero evicts immediately after commit. Unpruned contiguous suffixes remain readable.
        std::chrono::steady_clock::duration retention = std::chrono::minutes(10);
    };

    /// Projection preparation errors only, without disguising business failures as cursor errors.
    enum class Error {
        /// Missing name, invalid key, or deletion of absent projection; caller emits no event without visible change.
        Input,
        /// Current content/accounting exceeds local limits.
        Capacity,
        /// Cursor exhausted or requested position ahead of this Scope.
        Version,
        /// Complete contiguous suffix unavailable; capture a new baseline.
        History
    };

    /// One complete visible change. Encoder may choose data-only only with an existing Attr baseline.
    struct Event {
        /// Fixed shared address/key ownership.
        Key name;
        /// Complete public content; absent means deletion, while empty Buffer remains present.
        std::optional<Item> record;
        /// Contiguous Scope-view cursor, independent of source position.
        std::uint64_t version{};
        /// Ephemeris Data-only hint, not proof that a baseline exists.
        bool data{};
        /// Conservative event charge, excluding temporary network encoding.
        std::size_t bytes{};
        /// History-window time only, excluded from public content.
        std::chrono::steady_clock::time_point stored{};
        /// Atomic-batch first cursor; zero means ordinary single item.
        std::uint64_t first{};
        /// Complete atomic-batch cursor; recovery cannot start in the middle.
        std::uint64_t last{};
        /// Internal notification envelope only; empty in history entries.
        std::shared_ptr<const std::vector<Event>> batch{};
    };

    /// Point lookup captures name/content/cursor together; null record explicitly means missing.
    struct Point {
        /// Present only for existing records; schedulers may compare addresses for source identity without path concatenation.
        Key name;
        /// Shared native payloads without business deadlines.
        std::optional<Item> record;
        /// Current Scope cursor even when the key is absent.
        std::uint64_t version{};
    };

    /// O(1) frozen root; Views may outlive Scene without borrowing Scene or network services.
    class View {
    public:
        /// Captured complete visible cursor, zero for initial empty Scope.
        std::uint64_t version() const noexcept {
            return version_;
        }

        /// Captured record count, without rereading reusable pages.
        std::size_t size() const noexcept {
            return size_;
        }

        /// Captured conservative content bytes, not a hard physical-memory bound.
        std::size_t bytes() const noexcept {
            return bytes_;
        }

        /// Callback borrows key/public record and may reenter unlocked business objects or throw. Copy ownership to retain content.
        void each(auto&& reader) const {

            const auto root = root_;  // Read-section root constructed before Fence.
            const Fence fence{gate_}; // Synchronize before releasing root on normal and exceptional exit.
            root.each([&reader](const Name& name, const Item& record) { reader(name.key, record); });
        }

        /// Returns consumed rows. Offset is 0..size; false pauses before the current row, without rescanning page prefixes.
        std::size_t page(std::size_t offset, std::size_t maximum, auto&& reader) const {

            const auto root = root_;
            const Fence fence{gate_};
            return root.page(offset, maximum, [&reader](const Name& name, const Item& record) { return reader(name.key, record); });
        }

    private:
        friend class Scene;

        /// Writer-shared read-completion synchronization; shared_ptr::use_count alone creates no barrier.
        struct Fence {
            /// Independent lifetime for the original synchronization domain.
            std::shared_ptr<std::shared_mutex> gate;

            /// Pass through writer lock after the final read.
            ~Fence() {
                const std::shared_lock lock(*gate);
            }
        };

        /// Captures under domain lock without allocation/traversal; size is fixed with root.
        View(typename Tree::View root, std::uint64_t version, std::size_t bytes, std::shared_ptr<std::shared_mutex> gate) : root_(std::move(root)), version_(version), size_(root_.size()), bytes_(bytes), gate_(std::move(gate)) {}

        /// Complete public-content root.
        typename Tree::View root_;
        /// View cursor fixed with root.
        std::uint64_t version_{};
        /// Captured count, including valid zero.
        std::size_t size_{};
        /// Captured charge, unchanged by later writes.
        std::size_t bytes_{};
        /// Retains synchronization only, not service or Scope.
        std::shared_ptr<std::shared_mutex> gate_;
    };

    /// Commit returns notification/retired resources. Notify internal collector under domain; release the whole result outside.
    struct Retired {
        /// Actual commit notification exists even with zero history budget, independently of replay.
        Event event;
        /// Overwritten records retained to avoid releasing final payload ownership under lock.
        std::optional<Item> record;
        /// Eviction space reserved during prepare; commit allocates nothing.
        std::vector<Event> events;
    };

    /// Single-target preparation retained with source Edit before joint publication. Failure rolls back pending index/history changes.
    class Edit {
    public:
        /// Uncommitted destruction rolls back; Scene and the same domain lock must span its lifetime.
        ~Edit() {
            abort();
        }

        /// Transfers unique commit responsibility, disabling moved-from rollback.
        Edit(Edit&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), slot_(other.slot_), bytes_(other.bytes_), evicted_(other.evicted_), added_(other.added_), queued_(other.queued_), retired_(std::move(other.retired_)) {}

        /// End the current preparation explicitly; move assignment cannot overwrite an active commit or rollback owner.
        Edit& operator=(Edit&&) = delete;

        /// Keep one owner of prepared edit and its commit or rollback; copying is forbidden.
        Edit(const Edit&) = delete;

        /// Keep one owner of prepared edit and its commit or rollback; copying is forbidden.
        Edit& operator=(const Edit&) = delete;

        /// Noexcept content/index/cursor/history publication; caller commits source/scheduling/notification under the same domain lock.
        Retired commit() noexcept {

            ASTRA_PROFILE_SCOPE("star.scene.commit");

            auto& owner = *owner_;        // Consumed by one commit; a second call is forbidden.
            auto& event = retired_.event; // Complete prepared event, with no allocation remaining.
            if (event.record) {
                // Tree takes the immutable Name before history eviction; zero retention cannot invalidate entries_ keys.
                owner.tree_.set(slot_, added_ ? event.name : nullptr, *event.record);
            } else {
                owner.tree_.erase(slot_);
                owner.entries_.erase(event.name->key);
            }
            owner.bytes_ = bytes_;
            owner.version_ = event.version;
            for (std::size_t index = 0; index < evicted_; ++index) {
                owner.backlog_ -= owner.history_.front().bytes;
                retired_.events.push_back(std::move(owner.history_.front()));
                owner.history_.pop_front();
            }
            owner.editing_ = false;
            owner_ = nullptr;
            return std::move(retired_);
        }

    private:
        friend class Scene;

        /// Destructor owns all later preparation rollback; never advance the public cursor early.
        explicit Edit(Scene& owner) : owner_(&owner) {
            owner.editing_ = true;
        }

        /// Removes only new lookup/history tails; prepared pages retain original logical content.
        void abort() noexcept {

            if (!owner_) {
                return;
            }
            if (queued_) {
                owner_->backlog_ -= owner_->history_.back().bytes;
                owner_->history_.pop_back();
            }
            if (added_) {
                // Retired event still owns Name; remove borrowed index before member destruction releases it.
                owner_->entries_.erase(retired_.event.name->key);
            }
            owner_->editing_ = false;
            owner_ = nullptr;
        }

        /// Stable owning Scene for an uncommitted transaction; Scene cannot move.
        Scene* owner_{};
        /// Prepared page slot supporting allocation-free mutation.
        std::uint64_t slot_{};
        /// Postcommit current content charge.
        std::size_t bytes_{};
        /// History eviction count, possibly including the new item.
        std::size_t evicted_{};
        /// Whether rollback must remove a temporary lookup entry.
        bool added_{};
        /// Whether rollback must remove a temporary history tail.
        bool queued_{};
        /// Fixed notification and old content for off-lock release.
        Retired retired_;
    };

    /// One Scope projection candidate for source replacement/local atomic commit. Copies changed pages, not the full key hash table.
    /// Same outer domain lock spans preparation/commit; other Scopes may hold independent candidates.
    class Batch {
    public:
        /// Transfer old roots/history and complete notifications for off-lock reclamation, avoiding bulk-body destruction during swap.
        struct Retired {
            /// Old projection root, independently retained by old Views.
            Tree root;
            /// Old bounded history container, without payload-byte copies.
            std::unique_ptr<std::deque<Event>> history;
            /// Contiguous actual visible changes for internal notification.
            std::vector<Event> events;
        };

        /// Discard removes only new lookups, preserving root/cursor/history.
        ~Batch() {
            abort();
        }

        /// Unique candidate may move into a bounded Scope plan; moved-from candidate cannot roll back.
        Batch(Batch&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), tree_(std::move(other.tree_)), history_(std::move(other.history_)), events_(std::move(other.events_)), added_(std::move(other.added_)), removed_(std::move(other.removed_)), seen_(std::move(other.seen_)), bytes_(other.bytes_), backlog_(other.backlog_), version_(other.version_), retention_(other.retention_), failed_(other.failed_) {}

        /// End the current preparation explicitly; move assignment cannot overwrite an active commit or rollback owner.
        Batch& operator=(Batch&&) = delete;

        /// Keep one owner of prepared batch and its commit or rollback; copying is forbidden.
        Batch(const Batch&) = delete;

        /// Keep one owner of prepared batch and its commit or rollback; copying is forbidden.
        Batch& operator=(const Batch&) = delete;

        /// Reads original projection; each key may change once per batch. Input plans must first combine same-target changes.
        Point find(std::string_view key) const {
            const auto found = owner_->entries_.find(key);
            if (found == owner_->entries_.end()) {
                return {{}, {}, owner_->version_};
            }
            const auto row = owner_->tree_.find(found->second);
            return row.first && (*row.first)->key == key ? Point{*row.first, *row.second, owner_->version_} : Point{{}, {}, owner_->version_};
        }

        /// One visible Set/Erase per key. Any failure makes the entire batch discard-only, never partially committable.
        std::expected<void, Error> set(Key name, std::optional<Item> record, std::chrono::steady_clock::time_point now, bool data = false) {

            if (failed_ || !owner_ || !name || name->key.empty() || name->key.size() > 1024) {
                failed_ = true;
                return std::unexpected(Error::Input);
            }
            failed_ = true; // Allocation exceptions and failed results both disable candidate commit.
            if (version_ == UINT64_MAX) {
                return std::unexpected(Error::Version);
            }
            const auto found = owner_->entries_.find(name->key);
            const bool exists = found != owner_->entries_.end();
            if ((!record && !exists) || (data && (!record || !exists)) || seen_.contains(name->key)) {
                return std::unexpected(Error::Input);
            }
            auto slot = exists ? found->second : tree_.next();
            const auto old = exists ? owner_->tree_.find(slot) : std::pair<const Key*, const Item*>{};
            if (exists) {
                name = *old.first; // Reuse original public names instead of copying every string during replacement.
            }
            const auto before = exists ? owner_->weight(name->key, *old.second) : std::optional<std::size_t>(0);
            const auto after = record ? owner_->weight(name->key, *record) : std::optional<std::size_t>(0);
            if (!before || !after || *after > owner_->limits_.bytes || bytes_ - *before > owner_->limits_.bytes - *after || (!exists && owner_->entries_.size() - removed_.size() == owner_->limits_.records)) {
                return std::unexpected(Error::Capacity);
            }
            const auto metadata = sizeof(Event) + sizeof(Name) + name->key.size();
            const auto payload = record ? owner_->measure_(*record) : 0;
            if (payload > std::numeric_limits<std::size_t>::max() - metadata || metadata + payload > std::numeric_limits<std::size_t>::max() - backlog_) {
                return std::unexpected(Error::Capacity);
            }
            const auto cost = metadata + payload;
            events_.push_back(Event{name, record, version_ + 1, data, cost, now}); // Retain ownership before creating string_views.
            seen_.insert(name->key);
            if (!exists) {
                added_.push_back(name); // Reserve rollback ownership before emplace so failed allocation cannot leak directory entries.
                owner_->entries_.emplace(name->key, slot);
            } else if (!record) {
                removed_.push_back(name); // Old lookup entries are removed only at whole-batch commit.
            }
            tree_.prepare(slot);
            if (record) {
                tree_.set(slot, exists ? nullptr : name, *record);
            } else {
                tree_.erase(slot);
            }
            history_->push_back(events_.back());
            backlog_ += cost;
            while (!history_->empty() && (history_->size() > owner_->limits_.history || backlog_ > std::min(owner_->limits_.backlog, retention_) || (now >= history_->front().stored && now - history_->front().stored >= owner_->limits_.retention))) {
                backlog_ -= history_->front().bytes;
                history_->pop_front(); // Mutate only unpublished candidate history, never confirmed owner history.
            }
            bytes_ = bytes_ - *before + *after;
            ++version_;
            failed_ = false;
            return {};
        }

        /// Closes one public atomic batch. History boundaries and notification share first/last cursors; preparation failure publishes nothing.
        std::shared_ptr<const std::vector<Event>> seal() {
            for (auto& event : events_) {
                event.first = owner_->version_ + 1;
                event.last = version_;
            }
            for (auto& event : *history_) {
                if (event.version > owner_->version_) {
                    event.first = owner_->version_ + 1;
                    event.last = version_;
                }
            }
            return std::make_shared<const std::vector<Event>>(events_);
        }

        /// Call only after every Scope/source/scheduling candidate succeeds; allocation-free swap publishes complete contiguous changes.
        Retired commit() noexcept {

            ASTRA_PROFILE_SCOPE("star.scene.commit");

            assert(owner_ && !failed_);
            owner_->history_.swap(*history_); // Candidate containers are preallocated; commit cannot default-construct a potentially allocating deque.
            Retired retired{std::move(owner_->tree_), std::move(history_), std::move(events_)};
            owner_->tree_ = std::move(tree_);
            for (const auto& name : removed_) {
                owner_->entries_.erase(name->key);
            }
            owner_->bytes_ = bytes_;
            owner_->backlog_ = backlog_;
            owner_->version_ = version_;
            owner_->editing_ = false;
            owner_ = nullptr;
            return retired;
        }

        /// Actual retained candidate history for final cross-Scope budget checks.
        std::size_t history() const noexcept {
            return backlog_;
        }

    private:
        friend class Scene;

        /// Copies one root and bounded history while borrowing owner lookup. Construction failure does not set editing_.
        Batch(Scene& owner, std::size_t retention) : owner_(&owner), tree_(owner.tree_), history_(std::make_unique<std::deque<Event>>(owner.history_)), bytes_(owner.bytes_), backlog_(owner.backlog_), version_(owner.version_), retention_(retention) {
            owner.editing_ = true;
        }

        /// Root remains unpublished; remove only new lookups, without reverse compensation for old deletions/overwrites.
        void abort() noexcept {
            if (owner_) {
                for (const auto& name : added_) {
                    owner_->entries_.erase(name->key);
                }
                owner_->editing_ = false;
                owner_ = nullptr;
            }
        }

        /// Unique preparation responsibility, cleared on commit/move.
        Scene* owner_{};
        /// Candidate COW root shares owner's gate for read-completion synchronization.
        Tree tree_;
        /// Bounded candidate history; failure preserves owner's history.
        std::unique_ptr<std::deque<Event>> history_;
        /// Complete batch events whose name ownership covers borrowed indices below.
        std::vector<Event> events_;
        /// Prepared new lookups requiring rollback on failure.
        std::vector<Key> added_;
        /// Old lookups removed only at commit, without dangling strings.
        std::vector<Key> removed_;
        /// One change per key, without key-text copies.
        std::unordered_set<std::string_view> seen_;
        /// Candidate content charge.
        std::size_t bytes_{};
        /// Candidate retained-history charge.
        std::size_t backlog_{};
        /// Complete candidate cursor, never exposed before success.
        std::uint64_t version_{};
        /// Outer downstream-history allowance for this Scope.
        std::size_t retention_{};
        /// Any set failure/exception makes the whole batch discard-only.
        bool failed_{};
    };

    /// Required gate/measure and fixed limits; reads no Clock, starts no thread, and creates no source identity.
    Scene(std::shared_ptr<std::shared_mutex> gate, Measure measure, Limits limits) : gate_(std::move(gate)), measure_(measure), limits_(limits) {
        if (!gate_ || !measure_ || limits_.retention < decltype(limits_.retention)::zero()) {
            throw std::invalid_argument("Invalid projection configuration");
        }
    }

    /// Default local limits; construction is a valid empty projection at cursor zero.
    Scene(std::shared_ptr<std::shared_mutex> gate, Measure measure) : Scene(std::move(gate), measure, Limits{}) {}

    /// Views may outlive Scene; Edits and direct borrows cannot.
    ~Scene() = default;

    /// Keep one owner of writable projection and retained history; copying is forbidden.
    Scene(const Scene&) = delete;

    /// Keep one owner of writable projection and retained history; copying is forbidden.
    Scene& operator=(const Scene&) = delete;

    /// Version-zero baseline for an absent Scope; retains synchronization without pages, history, or permanent directory quota.
    static View empty(std::shared_ptr<std::shared_mutex> gate) {

        if (!gate) {
            throw std::invalid_argument("Empty projection requires a synchronization gate");
        }

        return View(Tree{}.capture(), 0, 0, std::move(gate));
    }

    /// Allocation-free root capture; caller first advances expiration and registers subsequent observation.
    View capture() const {

        ASTRA_PROFILE_SCOPE("star.scene.capture");
        idle();
        return View(tree_.capture(), version_, bytes_, gate_);
    }

    /// Unknown targets still return current Scope cursor, without node allocation or table snapshot.
    Point find(std::string_view key) const {

        idle();
        const auto found = entries_.find(key); // Direct string_view lookup, without temporary UUID/key text.
        if (found == entries_.end()) {
            return {{}, {}, version_};
        }
        const auto row = tree_.find(found->second); // One page lookup obtains shared native name and public record.
        return {*row.first, *row.second, version_};
    }

    /// Retained Scope-history charge for outer shared budgeting; preparation cannot expose pending tails.
    std::size_t history() const {
        idle();
        return backlog_;
    }

    /// Batch candidate for internal source replacement; ordinary writes keep the single-target Edit hot path.
    Batch prepare(std::size_t retention) {

        ASTRA_PROFILE_SCOPE("star.scene.prepare");
        idle();
        return Batch(*this, retention);
    }

    /// Only actual content changes. Absent record requires an existing target; data=true requires a complete existing record.
    std::expected<Edit, Error> prepare(Key name, std::optional<Item> record, std::chrono::steady_clock::time_point now, bool data = false, std::size_t retention = std::numeric_limits<std::size_t>::max()) {

        ASTRA_PROFILE_SCOPE("star.scene.prepare");

        idle();
        if (!name || name->key.empty() || name->key.size() > 1024) {
            return std::unexpected(Error::Input);
        }
        if (version_ == UINT64_MAX) {
            return std::unexpected(Error::Version);
        }
        const auto found = entries_.find(name->key); // Check visible presence and data-only shape before mutating lookup.
        const bool exists = found != entries_.end();
        if ((!record && !exists) || (data && (!record || !exists))) {
            return std::unexpected(Error::Input);
        }
        Edit edit(*this); // RAII rolls back all later fallible preparation, without partial projection publication.
        edit.retired_.event = Event{std::move(name), std::move(record), version_ + 1, data, 0, now};
        auto& event = edit.retired_.event;
        if (exists) {
            edit.slot_ = found->second;
            const auto row = tree_.find(edit.slot_);
            event.name = *row.first; // Existing entries reuse names instead of reallocating strings on overwrite.
            edit.retired_.record = *row.second;
        }
        const auto before = exists ? weight(event.name->key, *edit.retired_.record) : std::optional<std::size_t>(0);
        const auto after = event.record ? weight(event.name->key, *event.record) : std::optional<std::size_t>(0);
        if (!before || !after || *after > limits_.bytes || bytes_ - *before > limits_.bytes - *after || (!exists && entries_.size() == limits_.records)) {
            return std::unexpected(Error::Capacity);
        }
        edit.bytes_ = bytes_ - *before + *after;
        if (!exists) {
            edit.slot_ = tree_.next();
            // String_views borrow heap-owned immutable Name, not Event storage. Edit retains during preparation and tree retains after commit.
            entries_.emplace(event.name->key, edit.slot_);
            edit.added_ = true;
        }
        tree_.prepare(edit.slot_); // COW copies only necessary shared paths; renewal never calls this method.

        const auto metadata = sizeof(Event) + sizeof(Name) + event.name->key.size(); // Key limits bound fixed metadata.
        const auto payload = event.record ? measure_(*event.record) : 0;
        if (payload > std::numeric_limits<std::size_t>::max() - metadata || metadata + payload > std::numeric_limits<std::size_t>::max() - backlog_) {
            return std::unexpected(Error::Capacity);
        }
        event.bytes = metadata + payload;
        history_.push_back(event);
        backlog_ += event.bytes;
        edit.queued_ = true;
        auto retained = history_.size(); // Counts include the new item, which may commit without retention if it alone exceeds budget.
        auto backlog = backlog_;
        while (edit.evicted_ < history_.size() && (retained > limits_.history || backlog > std::min(limits_.backlog, retention) || (now >= history_[edit.evicted_].stored && now - history_[edit.evicted_].stored >= limits_.retention))) {
            backlog -= history_[edit.evicted_].bytes;
            --retained;
            ++edit.evicted_;
        }
        edit.retired_.events.reserve(edit.evicted_);
        return edit;
    }

    /// Complete contiguous suffix bounded by history entries/bytes. Current cursor returns empty; gaps cannot produce partial success.
    /// Since is fully installed position. Age prunes on writes; idle time alone cannot reject retained contiguous history.
    std::expected<std::vector<Event>, Error> replay(std::uint64_t since) const {

        ASTRA_PROFILE_SCOPE("star.scene.replay");

        idle();
        if (since > version_) {
            return std::unexpected(Error::Version);
        }
        if (since == version_) {
            return std::vector<Event>{};
        }
        if (history_.empty() || history_.front().version - 1 > since) {
            return std::unexpected(Error::History);
        }
        const auto first = std::upper_bound(history_.begin(), history_.end(), since, [](std::uint64_t value, const Event& event) { return value < event.version; });
        if (first != history_.end() && first->first && (since >= first->first || first->version != first->first)) {
            return std::unexpected(Error::History);
        }
        if (first == history_.end()) {
            return std::unexpected(Error::History);
        }
        return std::vector<Event>(first, history_.end());
    }

private:
    /// Prevents observing temporary lookups/history, without replacing thread synchronization.
    void idle() const {
        if (editing_) {
            throw std::logic_error("Projection has an unfinished edit");
        }
    }

    /// Bounded key metadata plus public payload costs; reject overflow instead of wrapping.
    std::optional<std::size_t> weight(std::string_view key, const Item& record) const noexcept {
        const auto metadata = sizeof(Item) + sizeof(Name) + key.size() + 128; // Conservative index/control-block allowance.
        const auto payload = measure_(record);                                // No network access or further allocation.
        return payload > std::numeric_limits<std::size_t>::max() - metadata ? std::nullopt : std::optional<std::size_t>(metadata + payload);
    }

    /// Domain commit lock shared by source and projection.
    const std::shared_ptr<std::shared_mutex> gate_;
    /// Fixed public-payload measure.
    const Measure measure_;
    /// Local limits independent of client requests.
    const Limits limits_;
    /// Owns names and outlives entries_ that borrows them.
    Tree tree_;
    /// Exact key to page slot. Tree retains active Names; Edit/Batch retain new temporary ones.
    std::unordered_map<std::string_view, std::uint64_t> entries_;
    /// Contiguous visible history, independent of source history.
    std::deque<Event> history_;
    /// Cursor survives deletion to empty and is never recycled.
    std::uint64_t version_{};
    /// Current logical visible-content charge.
    std::size_t bytes_{};
    /// Current retained-history charge.
    std::size_t backlog_{};
    /// At most one active two-phase mutation.
    bool editing_{};
};
} // namespace astra
