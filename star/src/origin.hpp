// Retain native records and source positions without adding domain-specific TTL or business-version policy.
#pragma once
#include "pages.hpp"
#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace astra {
/// Contiguous facts for one source Star/dynamic domain across all Sector/Spectrum pairs; not an Almanac or unified three-domain Store.
/// Item is a native Catalog/Ephemeris record. This container does not interpret TTL/orders/versions or select broadcast/projection content.
/// Except returned Views, reads/writes and Edit lifetime require outer serialization; const reads cannot overlap preparation. At most one transaction.
/// Remote Batch may prepare private roots/directories under source exclusion, but reacquires gate to publish, pairing with View completion barriers.
/// Commit transfers immutable references and native scalars. Item copy/move must be noexcept, enforced at template use.
template <typename Item, bool BinaryKey = false>
requires(std::is_nothrow_copy_constructible_v<Item> && std::is_nothrow_copy_assignable_v<Item> && std::is_nothrow_move_constructible_v<Item> && std::is_nothrow_move_assignable_v<Item>)
class Origin {
public:
    /// One key per source record; shared Scope text is neither concatenated into paths nor duplicated in Item.
    struct Name {
        /// Validated address shared by keys in the source Scope.
        std::shared_ptr<const Scope> scope;
        /// Raw UTF-8 key or 16-byte UUID, without Scope/source prefixes.
        std::string key;
    };

    /// Domain shape check: Catalog UTF-8 key or Ephemeris raw UUID. Caller retains full business validation.
    static bool validKey(std::string_view key) noexcept {
        if constexpr (BinaryKey) {
            if (key.size() != 16) {
                return false;
            }
            const auto bytes = reinterpret_cast<const std::uint8_t*>(key.data());
            return (bytes[6] & 0xf0U) == 0x40U && (bytes[8] & 0xc0U) == 0x80U;
        } else {
            return Scope::text(key, 1024);
        }
    }

    /// Source roots store native records without serializing Attr/Data/watermarks into KV Buffers.
    using Tree = Pages<Item, Name>;
    /// Allocation-free conservative payload measure, finite and overflow-safe; metadata is accounted separately.
    using Measure = std::size_t (*)(const Item&) noexcept;

    /// Group-level limits, without per-Scope history windows or an RSS guarantee.
    struct Limits {
        /// Native-record limit, default 65536; Catalog watermarks count too.
        std::size_t records = 65536;
        /// Active-Scope limit, default 4096. Empty Scopes can be reclaimed without resetting source position.
        std::size_t scopes = 4096;
        /// Conservative record/key/Scope/payload bytes, default 64 MiB.
        std::size_t bytes = 64 * 1024 * 1024;
        /// Local send-history entries, default 4096; remote construction disables send history.
        std::size_t history = 4096;
        /// Conservative history/payload-reference bytes, default 8 MiB; zero disables retention.
        std::size_t backlog = 8 * 1024 * 1024;
        /// Monotonic send-history age pruned on writes, default 10 minutes. Zero evicts even new history at commit; unpruned contiguous suffixes remain readable.
        std::chrono::steady_clock::duration retention = std::chrono::minutes(10);
    };

    /// Business version conflicts and ended leases are checked by native rules at final commit, not here.
    enum class Error {
        /// Invalid address/key/accounting/version input.
        Input,
        /// Duplicate Scope/key in a full snapshot; later items cannot overwrite earlier candidates.
        Duplicate,
        /// Native data or preparation metadata exceeds source hard limits.
        Capacity,
        /// Source position is not exactly +1 or is exhausted; never switches to per-Scope sequencing.
        Version,
        /// History cannot cover a complete contiguous suffix; recover a source baseline.
        History
    };

    /// Wire form follows the business fact. Retaining complete native history does not make Renew resend Attr/Data.
    enum class Form {
        /// Create, complete Catalog publication, or watermark with the domain's full fact.
        Record,
        /// Ephemeris Data/order only, without repeating fixed Attr.
        Data,
        /// Deadline/renewal-order refresh; receivers repair missing records.
        Renew,
        /// Authoritative Ephemeris source termination, distinct from receiver-local TTL deletion.
        Erase
    };

    /// Complete source change. Only local groups retain send history; remote groups have no relay log.
    struct Event {
        /// Immutable address/key ownership keeps history interpretable after current-record deletion.
        typename Tree::Key name;
        /// Complete native candidate, absent for authoritative termination. Adapter chooses data/renew/full wire form.
        std::optional<Item> record;
        /// Position within this source/domain; first commit is one, never derived from Scope counts.
        std::uint64_t position{};
        /// Native change form controlling source encoding; local maintenance is not a broadcast fact.
        Form form = Form::Record;
        /// Conservative history charge including referenced payloads, without shared-page RSS deduplication claims.
        std::size_t bytes{};
        /// Monotonic history-window time only, excluded from business records and wire deadlines.
        std::chrono::steady_clock::time_point stored{};
    };

    /// Release outside gate after commit so bulk history/payload reclamation cannot hold the business lock.
    struct Retired {
        /// Replaced native records whose final large payload reference must not release during locked page overwrite.
        std::optional<Item> record;
        /// Evicted complete events; prepare allocates the vector and commit only moves.
        std::vector<Event> events;
        /// Retains deleted Names so removing lookup entries cannot dangle string_views.
        typename Tree::Key name;
    };

    /// Immutable full-source root with position captured atomically. Read completion uses independent gate, permitting Views to outlive source.
    class View {
    public:
        /// Complete contiguous source position; empty source permits zero.
        std::uint64_t position() const noexcept {
            return position_;
        }

        /// Captured native record count, including Catalog watermarks.
        std::size_t size() const noexcept {
            return size_;
        }

        /// Conservative retained native bytes for send-recovery budgeting, not actual RSS.
        std::size_t bytes() const noexcept {
            return bytes_;
        }

        /// Callback borrows Scope/key/record outside gate and may throw. Copy shared ownership to retain records.
        void each(auto&& reader) const {

            const auto root = root_;  // Construct the traversal root before Fence.
            const Fence fence{gate_}; // Synchronize after the final read on normal/exceptional exit, then release root.
            root.each([&reader](const Name& name, const Item& record) { reader(*name.scope, name.key, record); });
        }

        /// Skips by active-row counts without rescanning each page's prefix; false pauses before the current item.
        std::size_t page(std::size_t offset, std::size_t maximum, auto&& reader) const {

            const auto root = root_;
            const Fence fence{gate_};
            return root.page(offset, maximum, [&reader](const Name& name, const Item& record) { return reader(*name.scope, name.key, record); });
        }

    private:
        friend class Origin;

        /// Pass through the writer's synchronization domain after the last read; use_count alone is no memory barrier.
        struct Fence {
            /// Independent lifetime for the original commit mutex.
            std::shared_ptr<std::shared_mutex> gate;

            /// Synchronize before releasing the temporary root.
            ~Fence() {
                const std::shared_lock lock(*gate);
            }
        };

        /// Construct only under gate, without traversal/allocation, fixing root, position, and synchronization domain.
        View(typename Tree::View root, std::uint64_t position, std::size_t bytes, std::shared_ptr<std::shared_mutex> gate) : root_(std::move(root)), position_(position), bytes_(bytes), size_(root_.size()), gate_(std::move(gate)) {}

        /// Captured complete page tree.
        typename Tree::View root_;
        /// Source position fixed with root.
        std::uint64_t position_{};
        /// Captured row/directory charge, unchanged by later source mutations.
        std::size_t bytes_{};
        /// Captured count, avoiding reusable-page reads during queries.
        std::size_t size_{};
        /// Does not retain source or network objects.
        std::shared_ptr<std::shared_mutex> gate_;
    };

    /// One send preparation: full root or contiguous history prefix, with head captured under the same gate.
    struct Delivery {
        /// Captured committed head, not peer ACK.
        std::uint64_t head{};
        /// Entire source root on history gaps, without per-Scope patching.
        std::optional<View> baseline;
        /// Bounded contiguous prefix, without copying complete retained history per peer.
        std::vector<Event> events;
    };

private:
    /// Lookup string_views borrow Names from pages; Edit retains new Names until commit.
    using Table = std::unordered_map<std::string_view, std::uint64_t>;

    /// Per-Scope direct lookup only, without its own source version/history/wheel.
    struct Group {
        /// Complete address shared by group keys.
        std::shared_ptr<const Scope> scope;
        /// Key to source-wide page slot, without body copies.
        Table entries;
    };

    /// Sector -> Spectrum directory without formatted single-string paths.
    using Groups = std::map<std::string, std::map<std::string, Group, std::less<>>, std::less<>>;

public:
    /// Active preparation prevents other Origin reads/writes. Caller may prepare independent projections, then commit all together.
    class Edit {
    public:
        /// Without commit, removes new lookup/history entries and preserves root/position; must finish under the same gate.
        ~Edit() {
            abort();
        }

        /// Transfers preparation responsibility, disabling moved-from rollback while retaining the same Origin binding.
        Edit(Edit&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), group_(other.group_), name_(std::move(other.name_)), record_(std::move(other.record_)), position_(other.position_), slot_(other.slot_), bytes_(other.bytes_), old_(other.old_), added_(other.added_), queued_(other.queued_), evicted_(other.evicted_), retired_(std::move(other.retired_)) {}

        /// Cannot replace an active preparation; end it explicitly first.
        Edit& operator=(Edit&&) = delete;

        /// Keep one owner of prepared edit and its commit or rollback; copying is forbidden.
        Edit(const Edit&) = delete;

        /// Keep one owner of prepared edit and its commit or rollback; copying is forbidden.
        Edit& operator=(const Edit&) = delete;

        /// Stable prepared name shared by projection/scheduling in the same atomic commit, without key formatting/copying.
        const typename Tree::Key& name() const noexcept {
            return name_;
        }

        /// Conservative candidate/directory charge, possibly slightly above final cost when deleting the last entry.
        std::size_t bytes() const noexcept {
            return bytes_ + owner_->directory_;
        }

        /// Final clock recheck may revise equal-cost native scalars such as deadlines, without changing payload budgets or turning deletion into insertion.
        /// Revises candidate/history under the same gate. False preserves the complete candidate.
        bool revise(const Item& record) noexcept {
            if (!owner_ || !record_ || owner_->measure_(record) != owner_->measure_(*record_)) {
                return false;
            }
            record_ = record;
            if (queued_) {
                owner_->history_.back().record = record;
            }
            return true;
        }

        /// Noexcept publication of source root, lookup, position, history, and accounting. Caller publishes projection under the same gate, then releases retired resources outside.
        Retired commit() noexcept {

            ASTRA_PROFILE_SCOPE("star.origin.commit");

            auto& owner = *owner_; // One valid owner; a second commit is an internal caller error.
            if (record_) {
                owner.tree_.set(slot_, added_ ? name_ : nullptr, std::move(*record_));
            } else if (old_) {
                owner.tree_.erase(slot_);
                group_->entries.erase(name_->key);
                --owner.records_;
            }
            if (added_) {
                ++owner.records_;
            }
            owner.bytes_ = bytes_;
            owner.position_ = position_;
            for (std::size_t index = 0; index < evicted_; ++index) {
                owner.backlog_ -= owner.history_.front().bytes;
                retired_.events.push_back(std::move(owner.history_.front()));
                owner.history_.pop_front();
            }
            if (group_ && group_->entries.empty()) {
                owner.prune(*name_->scope);
            }
            owner.editing_ = false;
            owner_ = nullptr;
            return std::move(retired_);
        }

    private:
        friend class Origin;

        /// Acquires single-item preparation responsibility at construction; later prepare owns every fallible step.
        explicit Edit(Origin& owner) : owner_(&owner), position_(owner.position_) {
            owner.editing_ = true;
        }

        /// Rollback removes only new directory/history entries, preserving existing prepared-page content/counts.
        void abort() noexcept {

            if (!owner_) {
                return;
            }
            if (queued_) {
                owner_->backlog_ -= owner_->history_.back().bytes;
                owner_->history_.pop_back();
            }
            if (added_) {
                group_->entries.erase(name_->key);
            }
            if (group_ && group_->entries.empty()) {
                owner_->prune(*group_->scope);
            }
            owner_->editing_ = false;
            owner_ = nullptr;
        }

        /// Borrows source before commit; caller guarantees source and gate lifetime.
        Origin* owner_{};
        /// Target group, possibly absent for a missing-key deletion.
        Group* group_{};
        /// Fixed address/key ownership.
        typename Tree::Key name_;
        /// Pending native candidate; absent means deletion.
        std::optional<Item> record_;
        /// New source position; maintenance may preserve the old value.
        std::uint64_t position_{};
        /// Existing/prepared page slot, unused for missing-key deletion.
        std::uint64_t slot_{};
        /// Postcommit active-row charge; Scope directories also obey the Scope count limit.
        std::size_t bytes_{};
        /// Whether the old record existed, determining deletion and retirement.
        bool old_{};
        /// New unpublished lookup entry, removed by rollback.
        bool added_{};
        /// Prepared send-history tail, removed by rollback.
        bool queued_{};
        /// Postcommit eviction count, possibly including the new item.
        std::size_t evicted_{};
        /// Retired large resources transferred for outer off-lock destruction.
        Retired retired_;
    };

    /// Preserving full-group merge candidate for Catalog high watermarks. Upserts unique targets; local mode prepares complete contiguous send history.
    /// Business layer owns native meaning and atomic visibility/validation; local sources cannot bypass contiguous positions.
    class Batch {
    public:
        /// Failure removes new lookup/empty groups while preserving old root, records, and source position.
        ~Batch() {
            abort();
        }

        /// Transfers unique rollback responsibility.
        Batch(Batch&& other) noexcept : owner_(std::exchange(other.owner_, nullptr)), tree_(std::move(other.tree_)), added_(std::move(other.added_)), removed_(std::move(other.removed_)), created_(std::move(other.created_)), seen_(std::move(other.seen_)), bytes_(other.bytes_), records_(other.records_), failed_(other.failed_), history_(std::move(other.history_)), position_(other.position_), backlog_(other.backlog_) {}

        /// End the current preparation explicitly; move assignment cannot overwrite an active commit or rollback owner.
        Batch& operator=(Batch&&) = delete;

        /// Keep one owner of prepared batch and its commit or rollback; copying is forbidden.
        Batch(const Batch&) = delete;

        /// Keep one owner of prepared batch and its commit or rollback; copying is forbidden.
        Batch& operator=(const Batch&) = delete;

        /// Candidate point lookup under source exclusion; copies immutable records rather than borrowing COW-replaceable pages.
        std::optional<Item> find(const Scope& scope, std::string_view key) const {
            const auto* group = owner_->locate(scope);
            if (!group) {
                return std::nullopt;
            }
            const auto found = group->entries.find(key);
            const auto row = found == group->entries.end() ? std::pair<const typename Tree::Key*, const Item*>{} : tree_.find(found->second);
            return row.first && (*row.first)->key == key && *(*row.first)->scope == scope ? std::optional<Item>(*row.second) : std::nullopt;
        }

        /// At most one modification per Scope/key in a candidate. Any failure requires discarding the entire batch, never committing a prepared subset.
        std::expected<typename Tree::Key, Error> set(const Scope& scope, std::string_view key, Item record, Form form = Form::Record) {

            if (failed_ || !owner_ || !scope.valid() || !validKey(key) || (owner_->local_ && form != Form::Record && form != Form::Renew)) {
                failed_ = true;
                return std::unexpected(Error::Input);
            }
            failed_ = true; // Every failure, including allocation exceptions, makes the candidate uncommittable.
            auto* group = owner_->locate(scope);
            const auto found = group ? group->entries.find(key) : typename Table::iterator{};
            const bool exists = group && found != group->entries.end();
            const auto slot = exists ? found->second : tree_.next();
            auto row = exists ? tree_.find(slot) : std::pair<const typename Tree::Key*, const Item*>{};
            if (exists && (!row.first || (*row.first)->key != key || *(*row.first)->scope != scope)) {
                return std::unexpected(Error::Duplicate); // Deleted directory entries remain until commit; never dereference an empty candidate page.
            }
            typename Tree::Key name = exists ? *row.first : nullptr;
            if (exists && seen_.contains(name.get())) {
                return std::unexpected(Error::Duplicate);
            }
            const auto before = exists ? owner_->weight(key, *row.second) : std::optional<std::size_t>(0);
            const auto after = owner_->weight(key, record);
            const auto extra = group ? 0 : directory(scope);
            if (!before || !after || *after > owner_->limits_.bytes || bytes_ - *before > owner_->limits_.bytes - *after || (!exists && records_ == owner_->limits_.records) || owner_->directory_ > owner_->limits_.bytes || extra > owner_->limits_.bytes - owner_->directory_ || bytes_ - *before + *after > owner_->limits_.bytes - owner_->directory_ - extra) {
                return std::unexpected(Error::Capacity);
            }
            if (!group) {
                if (owner_->scopes_ == owner_->limits_.scopes) {
                    return std::unexpected(Error::Capacity);
                }
                created_.reserve(created_.size() + 1); // Register rollback after obtain without further throwing.
                group = &owner_->obtain(scope);
                created_.push_back(group->scope);
            }
            if (!name) {
                name = std::make_shared<const Name>(group->scope, std::string(key));
                added_.push_back(Added{group, name}); // Retain name ownership before emplace so insertion failure can roll back safely.
                group->entries.emplace(name->key, slot);
            }
            seen_.insert(name.get());
            tree_.prepare(slot);
            tree_.set(slot, exists ? nullptr : name, record);
            bytes_ = bytes_ - *before + *after;
            records_ += !exists;
            if (history_) {
                if (position_ == UINT64_MAX) {
                    return std::unexpected(Error::Version);
                }
                const auto now = std::chrono::steady_clock::now();                     // Send history uses only monotonic local retention age.
                const auto metadata = sizeof(Event) + sizeof(Name) + name->key.size(); // History cost is independent of current source-row accounting.
                const auto payload = owner_->measure_(record);
                if (payload > std::numeric_limits<std::size_t>::max() - metadata || metadata + payload > std::numeric_limits<std::size_t>::max() - backlog_) {
                    return std::unexpected(Error::Capacity);
                }
                const auto cost = metadata + payload;
                history_->push_back(Event{name, record, ++position_, form, cost, now});
                backlog_ += cost;
                while (!history_->empty() && (history_->size() > owner_->limits_.history || backlog_ > owner_->limits_.backlog || now - history_->front().stored >= owner_->limits_.retention)) {
                    backlog_ -= history_->front().bytes;
                    history_->pop_front();
                }
            }
            failed_ = false;
            return name;
        }

        /// Final time recheck changes only equal-cost deadlines on already private pages, never a second business mutation.
        bool revise(const Scope& scope, std::string_view key, const Item& record) noexcept {
            if (!owner_ || failed_) {
                return false;
            }
            const auto* group = owner_->locate(scope); // Preparation fixes the directory; this method allocates nothing.
            if (!group) {
                return false;
            }
            const auto found = group->entries.find(key);
            if (found == group->entries.end()) {
                return false;
            }
            const auto row = tree_.find(found->second);
            if (!row.first || !seen_.contains(row.first->get()) || owner_->measure_(record) != owner_->measure_(*row.second)) {
                return false;
            }
            tree_.set(found->second, nullptr, record);
            if (history_) {
                for (auto iterator = history_->rbegin(); iterator != history_->rend() && iterator->position > owner_->position_; ++iterator) {
                    if (iterator->name->key == key && *iterator->name->scope == scope) {
                        iterator->record = record;
                        break;
                    }
                }
            }
            return true;
        }

        /// Allocation-free root/accounting publication; local mode also publishes contiguous position/history. Required retired receives old history for release with the returned root outside domain.
        Tree commit(std::unique_ptr<std::deque<Event>>* retired = nullptr) noexcept {

            ASTRA_PROFILE_SCOPE("star.origin.commit");
            assert(owner_ && !failed_ && (!history_ || retired));
            auto old = std::move(owner_->tree_);
            owner_->tree_ = std::move(tree_);
            owner_->bytes_ = bytes_;
            owner_->records_ = records_;
            if (history_) {
                owner_->history_.swap(*history_);
                owner_->position_ = position_;
                owner_->backlog_ = backlog_;
                *retired = std::move(history_);
            }
            for (const auto& item : removed_) {
                item.group->entries.erase(item.name->key);
            }
            for (const auto& item : removed_) {
                owner_->prune(*item.name->scope); // Detach all entries before reclaiming Group so no group pointer dangles.
            }
            owner_->editing_ = false;
            owner_ = nullptr;
            return old;
        }

        /// Caller checks complete native candidate costs, including shared bodies rather than pointer size alone.
        std::size_t bytes() const noexcept {
            return bytes_ + owner_->directory_;
        }

        /// Full replacement of one source Scope removes old candidate entries; each target may still change only once.
        std::expected<void, Error> erase(const Scope& scope, std::string_view key) {

            if (failed_ || !owner_ || owner_->local_) {
                failed_ = true;
                return std::unexpected(Error::Input);
            }
            failed_ = true;                      // Allocation failure must retain whole-Scope rollback responsibility.
            auto* group = owner_->locate(scope); // Borrowed through commit/discard; real directory entries remain until commit.
            const auto found = group ? group->entries.find(key) : typename Table::iterator{};
            if (!group || found == group->entries.end()) {
                return std::unexpected(Error::Input);
            }
            const auto row = owner_->tree_.find(found->second); // Original tree is unchanged; names/records belong to the Scope's old baseline.
            if (!row.first || (*row.first)->key != key || *(*row.first)->scope != scope) {
                return std::unexpected(Error::Duplicate); // New keys in this batch are absent from the original tree and cannot be removed as old entries.
            }
            if (!seen_.insert(row.first->get()).second) {
                return std::unexpected(Error::Duplicate);
            }
            removed_.push_back({group, *row.first});
            tree_.prepare(found->second);
            tree_.erase(found->second);
            bytes_ -= *owner_->weight(key, *row.second);
            --records_;
            failed_ = false;
            return {};
        }

    private:
        friend class Origin;

        /// Rollback responsibility for one new lookup entry; Group address remains stable through the transaction.
        struct Added {
            /// Fixed Group in the owner's address directory.
            Group* group{};
            /// Retains borrowed key text without copying payloads.
            typename Tree::Key name;
        };

        /// No key hash-table copy; pages use COW. Only local batches copy bounded history metadata, without bodies.
        explicit Batch(Origin& owner) : owner_(&owner), tree_(owner.tree_), bytes_(owner.bytes_), records_(owner.records_), history_(owner.local_ ? std::make_unique<std::deque<Event>>(owner.history_) : nullptr), position_(owner.position_), backlog_(owner.backlog_) {
            owner.editing_ = true;
        }

        /// Erase new entries before reclaiming new empty groups, preventing access through destroyed Group pointers.
        void abort() noexcept {
            if (owner_) {
                for (const auto& item : added_) {
                    item.group->entries.erase(item.name->key);
                }
                for (const auto& scope : created_) {
                    owner_->prune(*scope);
                }
                owner_->editing_ = false;
                owner_ = nullptr;
            }
        }

        /// Unique preparation owner, cleared after move/commit.
        Origin* owner_{};
        /// Initially shares the old root to force COW; publication still uses the live source's gate.
        Tree tree_;
        /// New lookup-entry rollback list.
        std::vector<Added> added_;
        /// Old entries detached only at commit; failure preserves real directory/names.
        std::vector<Added> removed_;
        /// New empty-group rollback list.
        std::vector<std::shared_ptr<const Scope>> created_;
        /// Deduplicates fixed names without copying key text.
        std::unordered_set<const Name*> seen_;
        /// Candidate row charge; temporary owner directories are isolated by editing_.
        std::size_t bytes_{};
        /// Candidate record count.
        std::size_t records_{};
        /// Any failure permanently disables candidate commit.
        bool failed_{};
        /// Local batches prepare bounded send-history copies without payload copying.
        std::unique_ptr<std::deque<Event>> history_;
        /// Contiguous positions per fact, published with the whole source root.
        std::uint64_t position_{};
        /// Candidate send-history charge.
        std::size_t backlog_{};
    };

    /// Private full-source candidate without capture APIs; no reader in another synchronization domain can access new pages before installation.
    class Draft {
    public:
        /// Discarding an incomplete baseline releases only the candidate, without accessing target or changing its position.
        ~Draft() = default;
        /// Transfers unique recovery ownership; moved-from candidates support only destruction/assignment.
        Draft(Draft&&) noexcept = default;
        /// Replaces a private candidate without installing it.
        Draft& operator=(Draft&&) noexcept = default;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft(const Draft&) = delete;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft& operator=(const Draft&) = delete;

        /// Adds one unique native record outside target gate; failure preserves complete installed state.
        std::expected<void, Error> set(const Scope& scope, std::string key, Item record) {

            if (!candidate_) {
                return std::unexpected(Error::Input);
            }
            Retired retired; // Even without old data/history, retain the same off-lock reclamation boundary.
            const std::lock_guard lock(*candidate_->gate_);
            if (candidate_->find(scope, key)) {
                return std::unexpected(Error::Duplicate);
            }
            auto edit = candidate_->prepare(scope, std::move(key), std::move(record), std::nullopt, std::chrono::steady_clock::now());
            if (!edit) {
                return std::unexpected(edit.error());
            }
            retired = edit->commit();
            return {};
        }

        /// Candidate's claimed complete position, revalidated against contiguous prefix and repair coverage at installation.
        std::uint64_t position() const noexcept {
            return position_;
        }

        /// Candidate native charge, excluding encoded network buffers.
        std::size_t bytes() const noexcept {
            return candidate_ ? candidate_->bytes_ + candidate_->directory_ : 0;
        }

        /// Point lookup copies immutable payload ownership without exposing a View in another synchronization domain.
        std::optional<Item> find(const Scope& scope, std::string_view key) const {
            return candidate_ ? candidate_->find(scope, key) : std::nullopt;
        }

        /// Borrows native entries/shared names for projection/scheduling preparation, without exposing mutable roots or another View synchronization domain.
        /// Reader may prepare other objects but must not reenter/mutate this Draft; shared names/content may be retained.
        void each(auto&& reader) const {
            if (candidate_) {
                candidate_->each(std::forward<decltype(reader)>(reader));
            }
        }

        /// Enumerates one Scope without rescanning the entire candidate per Scope.
        void each(const Scope& scope, auto&& reader) const {
            if (candidate_) {
                candidate_->each(scope, std::forward<decltype(reader)>(reader));
            }
        }

        /// Ordered bounded Scope inventory; copies addresses, not payloads or source cursors.
        std::vector<Scope> scopes() const {
            return candidate_ ? candidate_->scopes() : std::vector<Scope>{};
        }

    private:
        friend class Origin;

        /// Position is the full snapshot's claim; measure/limits are fixed from the receiving target.
        Draft(std::uint64_t position, Measure measure, Limits limits) : candidate_(std::make_unique<Origin>(std::make_shared<std::shared_mutex>(), measure, false, limits)), position_(position) {}

        /// Independent candidate/directory, never exposing Views or raw nodes to asynchronous readers.
        std::unique_ptr<Origin> candidate_;
        /// Source position cannot publish or ACK before complete.
        std::uint64_t position_{};
    };

    /// Retired full directory/root/history after installation, with unique lifetime so old state cannot mutate again.
    class Replaced {
    public:
        /// Destroy outside target gate; may release a large tree while old Views retain independent references.
        ~Replaced() = default;
        /// Transfers off-lock reclamation responsibility without restoring old source state.
        Replaced(Replaced&&) noexcept = default;
        /// Replace a nonempty retired owner only outside the lock to avoid synchronous old-tree reclamation.
        Replaced& operator=(Replaced&&) noexcept = default;

        /// Keep one owner of retired source state awaiting reclamation; copying is forbidden.
        Replaced(const Replaced&) = delete;

        /// Keep one owner of retired source state awaiting reclamation; copying is forbidden.
        Replaced& operator=(const Replaced&) = delete;

    private:
        friend class Origin;

        /// Takes swapped-out state without allocation.
        explicit Replaced(std::unique_ptr<Origin> value) : value_(std::move(value)) {}

        /// Destruction only; never revisit old pages through the candidate's old gate.
        std::unique_ptr<Origin> value_;
    };

    /// Local enables send history; remote groups never relay. Gate/measure are required. Construction takes no lock and starts no thread.
    Origin(std::shared_ptr<std::shared_mutex> gate, Measure measure, bool local, Limits limits) : gate_(std::move(gate)), measure_(measure), local_(local), limits_(limits) {
        if (!gate_ || !measure_ || limits_.retention < decltype(limits_.retention)::zero()) {
            throw std::invalid_argument("Invalid source configuration");
        }
    }

    /// Default group budget without per-Scope history copies.
    Origin(std::shared_ptr<std::shared_mutex> gate, Measure measure, bool local) : Origin(std::move(gate), measure, local, Limits{}) {}

    /// Edits and raw borrows cannot outlive source; returned Views/Items retain storage independently.
    ~Origin() = default;
    /// Stable Group/transaction addresses forbid copying or moving Origin.
    Origin(const Origin&) = delete;

    /// Keep one owner of source contents and commit synchronization; copying is forbidden.
    Origin& operator=(const Origin&) = delete;

    /// Allocates the next complete source position; exhaustion returns version without preincrementing.
    std::expected<std::uint64_t, Error> next() const {
        idle();
        return position_ == UINT64_MAX ? std::expected<std::uint64_t, Error>(std::unexpected(Error::Version)) : position_ + 1;
    }

    /// Current complete position, only outside preparation.
    std::uint64_t position() const {
        idle();
        return position_;
    }

    /// Logical row/directory charge for cross-source budgeting; forbidden during an active preparation.
    std::size_t bytes() const {
        idle();
        return bytes_ + directory_;
    }

    /// Direct native point lookup sharing payloads; unknown Scope/key creates no directory.
    std::optional<Item> find(const Scope& scope, std::string_view key) const {

        idle();
        const auto* group = locate(scope); // Borrows only existing directory state, without body traversal.
        if (!group) {
            return std::nullopt;
        }
        const auto found = group->entries.find(key);
        return found == group->entries.end() ? std::nullopt : std::optional<Item>(*tree_.at(found->second));
    }

    /// O(1) source/domain capture, not per-Scope snapshot-vector copies.
    View capture() const {

        ASTRA_PROFILE_SCOPE("star.origin.capture");
        idle();
        return View(tree_.capture(), position_, bytes_ + directory_, gate_);
    }

    /// Internal enumeration under source exclusion without another fenced View; remote private preparation may traverse the stable old root.
    /// Reader borrows shared names/records; cannot mutate this source or invoke application/network callbacks.
    void each(auto&& reader) const {

        idle();
        for (const auto& [sector, spectra] : groups_) {
            for (const auto& [spectrum, group] : spectra) {
                for (const auto& [key, slot] : group.entries) {
                    const auto row = tree_.find(slot);
                    reader(*row.first, *row.second);
                }
            }
        }
    }

    /// Enumerates one Scope in time proportional to its rows. Caller holds gate; no reentrant mutation.
    void each(const Scope& scope, auto&& reader) const {

        idle();
        if (const auto* group = locate(scope)) {
            for (const auto& [key, slot] : group->entries) {
                const auto row = tree_.find(slot); // Key borrows directory text; row borrows the immutable entry.
                reader(*row.first, *row.second);
            }
        }
    }

    /// Captures addresses only for per-Scope recovery preparation after releasing gate.
    std::vector<Scope> scopes() const {

        idle();
        std::vector<Scope> result; // Owned address copies; no Group borrows outside the lock.
        result.reserve(scopes_);
        for (const auto& [sector, spectra] : groups_) {
            for (const auto& [spectrum, group] : spectra) {
                result.push_back(*group.scope);
            }
        }
        return result;
    }

    /// Advance the complete boundary only after all Scopes install. Partial installation cannot call this; local send sources cannot be arbitrarily renumbered.
    bool confirm(std::uint64_t position) noexcept {
        if (local_ || editing_ || position < position_) {
            return false;
        }
        position_ = position;
        return true;
    }

    /// Prepares one target fact. Present position must be exactly +1; nullopt is only for Catalog/replica-local TTL maintenance without source history.
    /// Caller performs native/final-time validation; this container checks address/capacity/sequence. Failure neither publishes partial records nor reserves versions.
    std::expected<Edit, Error> prepare(const Scope& scope, std::string_view key, std::optional<Item> record, std::optional<std::uint64_t> position, std::chrono::steady_clock::time_point now, Form form = Form::Record) {

        ASTRA_PROFILE_SCOPE("star.origin.prepare");

        idle();
        if (!scope.valid() || !validKey(key)) {
            return std::unexpected(Error::Input);
        }
        if ((record && form == Form::Erase) || (!record && (form == Form::Data || form == Form::Renew))) {
            return std::unexpected(Error::Input);
        }
        if (position && (position_ == UINT64_MAX || *position != position_ + 1)) {
            return std::unexpected(Error::Version);
        }
        Edit edit(*this); // Edit owns all rollback responsibility from this point.
        edit.group_ = locate(scope);
        const auto found = edit.group_ ? edit.group_->entries.find(key) : typename Table::iterator{};
        edit.old_ = edit.group_ && found != edit.group_->entries.end();
        if (edit.old_) {
            edit.slot_ = found->second;
            auto row = tree_.find(edit.slot_); // One page lookup gets native record and shared name together.
            edit.retired_.record = *row.second;
            edit.name_ = *row.first;
        }
        const auto before = edit.old_ ? weight(edit.name_->key, *edit.retired_.record) : std::optional<std::size_t>(0);
        const auto after = record ? weight(key, *record) : std::optional<std::size_t>(0);
        if (!before || !after || *after > limits_.bytes || bytes_ - *before > limits_.bytes - *after || (record && !edit.old_ && records_ == limits_.records)) {
            return std::unexpected(Error::Capacity);
        }
        edit.bytes_ = bytes_ - *before + *after;
        const auto extra = record && !edit.group_ ? directory(scope) : 0; // Charge new-Scope directory cost once, not per key.
        if (directory_ > limits_.bytes || extra > limits_.bytes - directory_ || edit.bytes_ > limits_.bytes - directory_ - extra) {
            return std::unexpected(Error::Capacity);
        }
        if (!edit.name_) {
            if (record && !edit.group_) {
                if (scopes_ == limits_.scopes) {
                    return std::unexpected(Error::Capacity);
                }
                edit.group_ = &obtain(scope);
            }
            auto address = edit.group_ ? edit.group_->scope : std::make_shared<const Scope>(scope); // Even missing-key termination requires an independent history name.
            edit.name_ = std::make_shared<const Name>(std::move(address), std::string(key));
        }
        if (record && !edit.old_) {
            edit.slot_ = tree_.next();
            edit.group_->entries.emplace(edit.name_->key, edit.slot_);
            edit.added_ = true;
        }
        if (record || edit.old_) {
            tree_.prepare(edit.slot_); // Privatize only the path, without changing native content yet.
        }
        edit.retired_.name = edit.name_;
        edit.record_ = std::move(record);
        edit.position_ = position.value_or(position_);
        if (position && local_) {
            const auto metadata = sizeof(Event) + sizeof(Name) + edit.name_->key.size(); // Entry metadata outside the history container.
            const auto payload = edit.record_ ? measure_(*edit.record_) : 0;
            if (payload > std::numeric_limits<std::size_t>::max() - metadata) {
                return std::unexpected(Error::Capacity);
            }
            const auto cost = metadata + payload;
            if (cost > std::numeric_limits<std::size_t>::max() - backlog_) {
                return std::unexpected(Error::Capacity);
            }
            history_.push_back(Event{edit.name_, edit.record_, *position, edit.record_ ? form : Form::Erase, cost, now});
            backlog_ += cost;
            edit.queued_ = true;
        }
        auto retained = history_.size(); // Counts include the pending tail; budget eviction may include the new item.
        auto backlog = backlog_;
        while (edit.evicted_ < history_.size() && (retained > limits_.history || backlog > limits_.backlog || (now >= history_[edit.evicted_].stored && now - history_[edit.evicted_].stored >= limits_.retention))) {
            backlog -= history_[edit.evicted_].bytes;
            --retained;
            ++edit.evicted_;
        }
        edit.retired_.events.reserve(edit.evicted_); // Preallocate retirement capacity so commit cannot allocate.
        return edit;
    }

    /// Creates an empty candidate outside target lock, reading only fixed measure/limits. Does not set the source's live position.
    Draft prepare(std::uint64_t position) const {

        ASTRA_PROFILE_SCOPE("star.origin.prepare");
        return Draft(position, measure_, limits_);
    }

    /// Preserving internal merge is only for remote/merged containers; local sources require contiguous per-fact positions.
    Batch prepare() {

        ASTRA_PROFILE_SCOPE("star.origin.prepare");
        idle();
        if (local_) {
            throw std::logic_error("Local source requires ordered batch commits");
        }
        return Batch(*this);
    }

    /// Local atomic batches still assign contiguous per-fact positions and bounded history; maintenance cannot bypass the source log.
    Batch batch() {
        idle();
        if (!local_) {
            throw std::logic_error("Ordered batch requires local source");
        }
        return Batch(*this);
    }

    /// Only remote sources receive full baselines, permitting same-position repair without regression. Prepare projection/watermark/scheduling before joint publication after complete.
    /// Root swap neither traverses nor allocates. Reclaim returned state outside gate; local sources gain no arbitrary renumbering API.
    std::expected<void, Error> validate(const Draft& draft) const {

        idle();
        if (local_ || !draft.candidate_ || draft.candidate_->measure_ != measure_) {
            return std::unexpected(Error::Input);
        }
        if (draft.position_ < position_ || (draft.position_ == 0 && draft.candidate_->records_ != 0)) {
            return std::unexpected(Error::Version);
        }
        const auto& candidate = *draft.candidate_;
        if (candidate.records_ > limits_.records || candidate.scopes_ > limits_.scopes || candidate.directory_ > limits_.bytes || candidate.bytes_ > limits_.bytes - candidate.directory_) {
            return std::unexpected(Error::Capacity);
        }
        return {};
    }

    /// One whole-candidate swap for internal callers requiring container atomicity; staged recovery reuses only validate.
    std::expected<Replaced, Error> reset(Draft&& draft) {

        ASTRA_PROFILE_SCOPE("star.origin.reset");

        const auto valid = validate(draft);
        if (!valid) {
            return std::unexpected(valid.error());
        }
        auto& candidate = *draft.candidate_; // No escaping page readers exist, allowing transfer into the target synchronization domain.
        static_assert(std::is_nothrow_swappable_v<Tree> && noexcept(groups_.swap(candidate.groups_)) && noexcept(history_.swap(candidate.history_)));
        groups_.swap(candidate.groups_);
        std::swap(tree_, candidate.tree_);
        history_.swap(candidate.history_);
        std::swap(records_, candidate.records_);
        std::swap(scopes_, candidate.scopes_);
        std::swap(bytes_, candidate.bytes_);
        std::swap(directory_, candidate.directory_);
        std::swap(backlog_, candidate.backlog_);
        position_ = draft.position_;
        return Replaced(std::move(draft.candidate_));
    }

    /// Owns complete contiguous suffix events while sharing payloads. Future/gapped requests never return misleading partial success.
    /// Since is fully installed position. Age affects write-time pruning, not read-time validity of a complete suffix.
    std::expected<std::vector<Event>, Error> replay(std::uint64_t since) const {

        ASTRA_PROFILE_SCOPE("star.origin.replay");

        idle();
        if (since > position_) {
            return std::unexpected(Error::Version);
        }
        if (since == position_) {
            return std::vector<Event>{};
        }
        if (history_.empty() || history_.front().position - 1 > since) {
            return std::unexpected(Error::History);
        }
        const auto begin = std::upper_bound(history_.begin(), history_.end(), since, [](std::uint64_t value, const Event& event) { return value < event.position; });
        if (begin == history_.end()) {
            return std::unexpected(Error::History);
        }
        return std::vector<Event>(begin, history_.end());
    }

    /// Captures a complete contiguous prefix within count/bytes. Oversized first entry returns capacity without skipping or splitting commits.
    /// History gaps return an O(1) full-source baseline; unpruned old history remains sendable. Never advance since early; encode/send after releasing gate.
    std::expected<Delivery, Error> deliver(std::uint64_t since, std::size_t count, std::size_t bytes) const {

        ASTRA_PROFILE_SCOPE("star.origin.deliver");

        idle();
        if (!local_ || count == 0 || bytes == 0) {
            return std::unexpected(Error::Input);
        }
        if (since > position_) {
            return std::unexpected(Error::Version);
        }
        Delivery result{position_, {}, {}}; // No tail means no event-vector allocation.
        if (since == position_) {
            return result;
        }
        const auto begin = std::upper_bound(history_.begin(), history_.end(), since, [](std::uint64_t value, const Event& event) { return value < event.position; });
        if (begin == history_.end() || begin->position - 1 != since) {
            result.baseline.emplace(capture());
            return result;
        }

        std::size_t used{}; // Charge complete native events including payload references, not just vector elements.
        auto end = begin;
        for (; end != history_.end() && static_cast<std::size_t>(end - begin) < count; ++end) {
            if (end->bytes > bytes - used) {
                if (end == begin) {
                    return std::unexpected(Error::Capacity);
                }
                break;
            }
            used += end->bytes;
        }
        result.events.assign(begin, end); // Allocate exactly this complete prefix, never an arbitrary huge count capacity.
        return result;
    }

private:
    /// Conservative directory/address/bucket reserve; validated 128-byte identifiers keep sums bounded.
    static std::size_t directory(const Scope& scope) noexcept {
        return 512 + 2 * (scope.sector.size() + scope.spectrum.size());
    }

    /// Prevents observing temporary directories or opening a second preparation; not a replacement for external locking.
    void idle() const {
        if (editing_) {
            throw std::logic_error("Source has an unfinished edit");
        }
    }

    /// Conservative native row cost includes page/directory/Name overhead; Scope directories also obey a separate count limit.
    std::optional<std::size_t> weight(std::string_view key, const Item& record) const noexcept {

        const auto metadata = sizeof(Item) + sizeof(Name) + key.size() + 128; // Fixed index/control-block allowance, not exact allocator accounting.
        const auto payload = measure_(record);                                // Allocation-free payload cost supplied by the native type.
        return payload > std::numeric_limits<std::size_t>::max() - metadata ? std::nullopt : std::optional<std::size_t>(metadata + payload);
    }

    /// Direct address lookup without allocation for missing Scopes; caller retains gate and Group lifetime.
    Group* locate(const Scope& scope) {
        const auto sector = groups_.find(scope.sector);
        if (sector == groups_.end()) {
            return nullptr;
        }
        const auto spectrum = sector->second.find(scope.spectrum);
        return spectrum == sector->second.end() ? nullptr : &spectrum->second;
    }

    /// Const lookup shares directory rules without exposing mutation through const_cast.
    const Group* locate(const Scope& scope) const {
        const auto sector = groups_.find(scope.sector);
        if (sector == groups_.end()) {
            return nullptr;
        }
        const auto spectrum = sector->second.find(scope.spectrum);
        return spectrum == sector->second.end() ? nullptr : &spectrum->second;
    }

    /// After checking Scope capacity, prepare an empty group; allocation failure leaves no new empty Sector.
    Group& obtain(const Scope& scope) {

        auto address = std::make_shared<const Scope>(scope);
        auto [sector, created] = groups_.try_emplace(scope.sector);
        try {
            auto [spectrum, inserted] = sector->second.try_emplace(scope.spectrum, Group{std::move(address), {}});
            scopes_ += inserted;
            if (inserted) {
                directory_ += directory(scope);
            }
            return spectrum->second;
        } catch (...) {
            if (created) {
                groups_.erase(sector);
            }
            throw;
        }
    }

    /// Reclaims only empty Scope directories, preserving source position and addresses retained by snapshots/history.
    void prune(const Scope& scope) noexcept {

        const auto sector = groups_.find(scope.sector);
        if (sector == groups_.end()) {
            return;
        }
        const auto spectrum = sector->second.find(scope.spectrum);
        if (spectrum != sector->second.end() && spectrum->second.entries.empty()) {
            directory_ -= directory(scope); // Compute before releasing Group's final Scope reference.
            sector->second.erase(spectrum);
            --scopes_;
        }
        if (sector->second.empty()) {
            groups_.erase(sector);
        }
    }

    /// Conservative directory charge shares the total byte budget with row costs.
    std::size_t directory_{};
    /// Outer shared commit mutex; Views retain its synchronization lifetime independently.
    const std::shared_ptr<std::shared_mutex> gate_;
    /// Native measure fixed at construction.
    const Measure measure_;
    /// Only local sources retain send history.
    const bool local_;
    /// Source-level static limits.
    const Limits limits_;
    /// Complete native source root.
    Tree tree_;
    /// Directory destroys before tree_, which retains borrowed key text until afterward.
    Groups groups_;
    /// Bounded contiguous local history; empty for remote groups.
    std::deque<Event> history_;
    /// One position shared across Scopes.
    std::uint64_t position_{};
    /// Current native row count, initially zero.
    std::size_t records_{};
    /// Current nonempty or temporarily prepared Scope count.
    std::size_t scopes_{};
    /// Conservative current row charge, initially zero.
    std::size_t bytes_{};
    /// Retained history charge; editing_ prevents observation while an uncommitted tail is included.
    std::size_t backlog_{};
    /// One prepare/commit at a time; not an atomic cross-thread flag.
    bool editing_{};
};
} // namespace astra
