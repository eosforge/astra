// Own authoritative Almanac versions, consistent views, and atomic state publication.
#pragma once
#include "snapshot_index.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <expected>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace astra {
/// Almanac replica for one Sector/Spectrum. Accepts already authenticated Polaris data; handles neither admission nor networking.
/// No Store-local versions, TTLs, or wheel. Baselines use authoritative versions; increments require +1. Readers cannot mutate state.
class Almanac {
    /// Private lookup and page-index state, not a cross-component data format.
    struct State;

public:
    /// Uses existing byte ownership; an empty Buffer is a valid empty value.
    using Buffer = std::vector<std::uint8_t>;
    /// Accepted payloads have only immutable shared references, without caller-owned writable aliases.
    using Value = std::shared_ptr<const Buffer>;

    /// Native errors mapped by the RPC adapter. Allocation failures still throw bad_alloc rather than impersonating version conflicts.
    enum class Error {
        /// Invalid key/body or a consumed baseline draft.
        Input,
        /// Configured Scope content or record limit exceeded.
        Capacity,
        /// Duplicate snapshot key; later pages cannot overwrite earlier entries.
        Duplicate,
        /// Baseline regression, increment gap, zero patch version, or exhausted version; preserves complete state.
        Version,
        /// No complete baseline installed; default empty memory is not an authoritative empty Scope.
        Unready,
        /// Complete contiguous history is unavailable; capture a new baseline.
        History
    };

    /// Per-Scope content/history limits, excluding process RSS and cross-Scope recovery budgets.
    /// Outer admission must jointly account for concurrent preparation, old views, index metadata, and network buffers.
    struct Limits {
        /// Current records: default 65536; zero permits only an empty Scope.
        std::size_t records = 65536;
        /// Current key/value bytes: default 64 MiB; zero permits only an empty Scope.
        std::size_t bytes = 64 * 1024 * 1024;
        /// Per-key history entries: default 1000, retained/evicted by complete version. Zero requires a new baseline for old cursors.
        std::size_t history = 1000;
        /// History Change/key/value accounting: default 8 MiB; zero disables retention.
        std::size_t backlog = 8 * 1024 * 1024;
    };

    /// Per-key change in a complete authoritative commit; batch members share a version. Same-value Set and missing-key Delete retain commit evidence.
    struct Change {
        /// Owned immutable key of 1..1024 bytes, shared with lookup and index.
        std::shared_ptr<const std::string> key;
        /// Nonnull means complete Set, including empty bytes; null means Delete.
        Value value;
        /// Scope version assigned by Polaris; valid increments are 1..UINT64_MAX.
        std::uint64_t version{};
        /// Complete batch for internal notification only; individual history entries do not retain it.
        std::shared_ptr<const std::vector<Change>> batch{};

        /// Conservative logical history cost, excluding allocator and container overhead.
        std::size_t bytes() const noexcept;
    };

    /// Immutable root and authoritative version captured at one commit boundary, without scanning or copying the whole Map.
    /// May outlive Almanac; retains only pages and an independent read-completion mutex, without network ownership.
    class View {
    public:
        /// Captured authoritative version. Zero is an installed empty baseline, distinct from unready.
        std::uint64_t version() const noexcept;
        /// Captured record count, without reading reusable pages.
        std::size_t size() const noexcept;
        /// Captured logical key/value bytes, fixed with the root for the outer shared preparation budget.
        std::size_t bytes() const noexcept;

        /// Borrows key/value during reader, which may throw and runs outside business locks.
        /// Copy Value ownership or key text to retain data; never keep the supplied references.
        /// May reenter live Almanac operations. Exit still acquires the commit mutex, without a bounded-wait guarantee.
        /// Outer locks must follow commit lock order to avoid inverse waits.
        void each(auto&& reader) const {

            // Construct root before fence so read-completion synchronization precedes root release; use_count is not a barrier.
            const auto root = root_;
            const Fence fence{gate_};
            root.each([&reader](const std::string& key, const Index::Record& record) { reader(key, record.value); });
        }

        /// Uses each's completion synchronization, visiting at most maximum entries. Reader may return false to pause at a byte budget.
        /// Offset counts entries consumed from this view; returns newly visited entries without copying the table or changing persistence versions.
        std::size_t page(std::size_t offset, std::size_t maximum, auto&& reader) const {

            const auto root = root_;  // Retain the root for this segment independently of the view owner.
            const Fence fence{gate_}; // Synchronize before releasing the temporary root on success and exception.
            return root.page(offset, maximum, [&reader](const std::string& key, const Index::Record& record) { return reader(key, record.value); });
        }

    private:
        friend class Almanac;

        /// At read completion, pass through the writer's mutex before releasing this root reference.
        struct Fence {
            /// Owns mutex lifetime independently of Almanac/Client addresses.
            std::shared_ptr<std::mutex> gate;
            /// Synchronizes after the final page read, including reader exceptions.
            ~Fence();
        };

        /// Constructed only under Almanac's lock with one root, authoritative version, content charge, and synchronization domain.
        View(Index::View root, std::uint64_t version, std::size_t bytes, std::shared_ptr<std::mutex> gate);
        /// Captured tree; later writes copy only necessary shared paths.
        Index::View root_;
        /// Authoritative version fixed with root_.
        std::uint64_t version_{};
        /// Captured count avoids inspecting reusable internal pages.
        std::size_t size_{};
        /// Captured logical content charge, unchanged by later writes.
        std::size_t bytes_{};
        /// Independent synchronization domain retained by Views after Almanac destruction.
        std::shared_ptr<std::mutex> gate_;
    };

    /// Privately prepared baseline; interrupted paging, duplicate keys, and allocation failure preserve current state until reset succeeds.
    /// Owned by one recovery task, without concurrent mutation or a synthetic network-complete marker.
    class Draft {
    public:
        /// Discards only private pages/payloads without accessing Almanac.
        ~Draft();
        /// Transfers the unique candidate; the moved-from object supports only destruction or assignment.
        Draft(Draft&&) noexcept;
        /// Replaces the private candidate without installing into any Almanac.
        Draft& operator=(Draft&&) noexcept;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft(const Draft&) = delete;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft& operator=(const Draft&) = delete;
        /// Owns one unique key/value. Failure or exception preserves existing candidate content.
        /// Key is 1..1024 bytes, value at most 1 MiB. A version-zero baseline must be empty.
        std::expected<void, Error> set(std::string key, Buffer value);

    private:
        friend class Almanac;
        /// Created only by prepare with authoritative baseline version and fixed limits.
        Draft(std::uint64_t version, Limits limits);
        /// Unique off-lock candidate, empty after transfer or successful installation.
        std::unique_ptr<State> state_;
        /// Preparation limits; reset also checks the destination Almanac's limits.
        Limits limits_;
    };

    /// Single-key lookup and version captured together without a group snapshot.
    struct Point {
        /// Complete Scope version, even when the target key is absent.
        std::uint64_t version{};
        /// Null means missing; nonnull empty bytes mean a present empty record.
        Value value;
    };

    /// Owned bounded contiguous history sharing payloads with current/history state, without copying Buffers.
    struct Replay {
        /// Complete covered version; empty changes are allowed only when already at that version.
        std::uint64_t version{};
        /// All complete per-key commits in increasing version order, without merging repeated keys.
        std::vector<Change> changes;
    };

    /// Logical accounting captured under a short lock; excludes externally retained old Views and does not represent RSS.
    struct Usage {
        /// Current logical key/value bytes.
        std::size_t bytes{};
        /// Retained incremental-history cost.
        std::size_t history{};
        /// Fully installed version; absent when unready, zero for a valid empty baseline.
        std::optional<std::uint64_t> version;
    };

    /// Creates an unready Scope with default limits, without implying a Polaris baseline.
    Almanac();
    /// Copies fixed limits; creates no clock, thread, or network callback.
    explicit Almanac(Limits limits);
    /// Stop direct access before destruction; returned Views and Values may survive independently.
    ~Almanac();

    /// Keep one owner of authoritative contents, history, and synchronization; copying is forbidden.
    Almanac(const Almanac&) = delete;

    /// Keep one owner of authoritative contents, history, and synchronization; copying is forbidden.
    Almanac& operator=(const Almanac&) = delete;
    /// Creates an empty private candidate at the specified version, even before readiness.
    Draft prepare(std::uint64_t version) const;
    /// Call only after the network layer confirms completeness. A newer baseline replaces all records and clears history; the first may be empty version zero.
    /// True installs, false means same-version replay; lower versions fail. Failure preserves the draft; success consumes it.
    std::expected<bool, Error> reset(Draft&& draft);
    /// Single-key Set/Delete at exactly current +1. Nullopt deletes; an empty Buffer is a valid Set.
    /// Nonzero replay within the installed range returns false; a new commit returns true. Failure preserves state and version.
    /// Optional outer history-byte allowance; default adds no limit and cannot change whether a valid write commits.
    /// Optionally receives an immutable committed change even with no history budget. Failure leaves it unchanged.
    std::expected<bool, Error> apply(std::uint64_t version, std::string key, std::optional<Buffer> value, std::size_t retention = std::numeric_limits<std::size_t>::max(), Change* committed = nullptr);
    /// Atomically publishes one nonempty unique-key batch at one authoritative version, without extra batch limits. Single-value/storage limits still apply; failure preserves root/version.
    std::expected<bool, Error> apply(std::uint64_t version, std::vector<Change> changes, std::size_t retention, Change* committed = nullptr);
    /// Captures root, count, and version under a short lock; an absent baseline returns unready, never a temporary empty View.
    std::expected<View, Error> view() const;
    /// Direct lookup without creating entries or changing versions. Empty/oversized keys return input.
    std::expected<Point, Error> find(std::string_view key) const;
    /// Complete contiguous history after since through current. Future cursors return version; insufficient history returns history.
    /// Bounded by history entry/byte limits; allocation failure propagates without affecting committed data.
    std::expected<Replay, Error> replay(std::uint64_t since) const;
    /// Reads logical content/history usage and installed version without copying roots or scanning records.
    Usage usage() const;

private:
    /// Checks key/value lengths and NULs. Callers first validate UTF-8, identity, and the sector __ boundary.
    static bool valid(std::string_view key, const Buffer* value) noexcept;
    /// Fixed local limits, not negotiated protocol values.
    const Limits limits_;
    /// One independent synchronization domain; Views extend its lifetime without retaining Almanac or the service.
    const std::shared_ptr<std::mutex> gate_ = std::make_shared<std::mutex>();
    /// Current state accessed only under gate_. Baseline swap reclaims old state outside the lock.
    std::unique_ptr<State> state_;
    /// Whether reset installed a complete baseline; initially false, independently of version zero.
    bool ready_{};
    /// Contiguous complete +1 commits, empty after reset and protected by the same commit guard.
    std::deque<Change> history_;
    /// Logical history-byte total; eviction subtracts each item's actual charge.
    std::size_t historyBytes_{};
};
} // namespace astra
