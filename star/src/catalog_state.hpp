// Coordinate Catalog native sources, merged views, quotas, and scheduled expiry.
#pragma once
#include "agenda.hpp"
#include "borrowing.hpp"
#include "catalog.hpp"
#include "context.hpp"
#include "origin.hpp"
#include "reading.hpp"
#include "restore.hpp"
#include "scene.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace astra {
/// Commits the local Catalog source and retains expired version watermarks. Only direct publish/renew assigns positions; local cleanup never broadcasts.
/// RPC callers validate Session/instance and retain Access::Permit until return. State calls no application callbacks or network operations.
class Catalog::State {
public:
    /// One source position covers this Star's Catalog Scopes.
    using Source = Origin<Record>;

    /// Public projection contains only application version/body; deadline changes create no page copy or observation event.
    struct Content {
        /// Positive content version, distinct from Scope cursor and source position.
        std::uint64_t version{};
        /// Complete immutable body, including valid empty bytes.
        Value value;
    };

    /// Names/bodies shared with source; subscribers see no deadlines.
    using Projection = Scene<Content, Source::Name>;
    /// Sampled under the final commit lock; production uses the real Clock.
    using Time = std::move_only_function<std::optional<Clock::Reading>()>;
    /// Bounded internal collector, without external user callbacks.
    using Notify = void (*)(void*, const Scope&, const Projection::Event&) noexcept;

    /// Separates business rejection from capacity/history errors. RPC maps allocation exceptions to resource exhaustion.
    enum class Error {
        /// Invalid input, Scope, key, payload, or content version.
        Input,
        /// No usable local application time, distinct from temporary Pulsar disconnection.
        Clock,
        /// No live local body; a watermark alone cannot support Renew.
        Ended,
        /// Below the highest application version, or Renew differs from the local version.
        Version,
        /// Different complete body at the same application version.
        Conflict,
        /// Source position, view cursor, or absolute deadline exhausted.
        Exhausted,
        /// Source/Scope/view capacity exhausted; failed preparation publishes no business write.
        Capacity,
        /// Cursor cannot be recovered completely; use a full view.
        History
    };

    /// All Scopes share bounded source capacity and one downstream history-byte budget; empty Scopes allocate no wheel.
    struct Limits {
        /// Native/send-history limits: default 64 MiB/8 MiB and 65536 rows.
        Source::Limits source;
        /// Per-Scope content/history limits, additionally bounded by total scopes/history.
        Projection::Limits projection;
        /// Opened-Scope limit; empty Scopes retain their cursors and never reuse positions.
        std::size_t scopes = 4096;
        /// Total logical downstream-history bytes across Scopes.
        std::size_t history = 8 * 1024 * 1024;
        /// Remote-source limit, independent of Scope count.
        std::size_t replicas = 63;
        /// Total logical native bytes across remote sources.
        std::size_t replicaBytes = 128 * 1024 * 1024;
    };

    /// Uses Star's Unix-epoch Clock without a new clock or thread; initially empty at source position zero.
    explicit State(Clock& clock);
    /// Required sequential time provider for deterministic component tests; must not reenter State. Construction does not sample.
    State(Time time, Limits limits);
    /// Stop direct calls and notification receivers before destruction; captured content/source Views may remain readable.
    ~State();

    /// Keep one owner of domain sources, projections, and commit synchronization; copying is forbidden.
    State(const State&) = delete;

    /// Keep one owner of domain sources, projections, and commit synchronization; copying is forbidden.
    State& operator=(const State&) = delete;

    /// Installs an internal noexcept commit notification. Caller retains context and stops old use before replacement.
    void notify(Notify notify, void* context);
    /// Full single-key publication. Positive versions may skip; equal-version/equal-body retry may refresh TTL without content notification.
    std::expected<void, Error> publish(const Scope& scope, std::string_view key, Value value, std::uint64_t version, std::uint32_t ttl);

    /// Complete entry within one Scope; the batch shares the caller's version and TTL.
    struct Entry {
        /// Unique UTF-8 key, 1..1024 bytes.
        std::string key;
        /// Nonnull for Publish, null for Renew; watermarks cannot restore bodies.
        Value value;
    };

    /// At most 128 entries and 1 MiB total keys/bodies, committed once across source/projection/snapshots. Any rejection preserves every key.
    std::expected<void, Error> publish(const Scope& scope, std::span<const Entry> entries, std::uint64_t version, std::uint32_t ttl, bool renewal = false);
    /// Extends only a live local body. Explicit TTL on every call, 1 s..10 min; watermarks cannot restore bodies.
    std::expected<void, Error> renew(const Scope& scope, std::string_view key, std::uint64_t version, std::uint32_t ttl);
    /// Captures highest versions for 1..128 unique keys under one shared lock; unknown is zero and expiration retains watermarks.
    /// Output follows keys without allocating versions, creating Scopes, or scanning the source table.
    std::expected<std::vector<std::uint64_t>, Error> versions(const Scope& scope, std::span<const std::string_view> keys) const;
    /// Advances all elapsed full ticks. Failure propagates without claiming catch-up; earlier complete expirations remain committed.
    void tick();
    /// Advances expiration then captures one public Scope. Missing Scopes return an empty root at cursor zero without directory allocation.
    std::expected<Projection::View, Error> capture(const Scope& scope);
    /// Point lookup after expiration, without a table snapshot; returns explicit absence and Scope cursor.
    std::expected<Projection::Point, Error> find(const Scope& scope, std::string_view key);
    /// Contiguous visible changes after advancing expiration; renewals are excluded.
    std::expected<std::vector<Projection::Event>, Error> changes(const Scope& scope, std::uint64_t since);
    /// Complete local-source state or contiguous send history; deadline refreshes are distinct from downstream content changes.
    Source::View source();
    /// Copy local-source history after since under the export lock; return mapped input or retained-history failures.
    std::expected<std::vector<Source::Event>, Error> events(std::uint64_t since);

    /// Targeted repair captures complete fact and position at one source boundary, without scanning all Scopes.
    struct Point {
        /// Contiguous local-source head, distinct from public view cursor.
        std::uint64_t position{};
        /// Current complete source fact, absent if unknown.
        std::optional<Record> record;
    };

    /// Validate the address and capture its local-source record plus cursor under the export lock, preserving absolute deadlines.
    std::expected<Point, Error> resolve(const Scope& scope, std::string_view key);
    /// True when the complete prefix or targeted repair already covers this target; confirms position only by contiguous rules.
    std::expected<bool, Error> covered(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key);
    /// Captures a bounded suffix or complete baseline at one commit boundary; encode outside the domain lock.
    std::expected<Source::Delivery, Error> deliver(std::uint64_t since, std::size_t count, std::size_t bytes);
    /// Only verified replication control admits sources; a trusted replacement prevents old identity readmission.
    std::expected<void, Error> admit(std::string_view id);
    /// Rejects new facts from the old source while existing bodies expire normally; merged watermarks never regress.
    void retire(std::string_view id);
    /// Contiguous source position, excluding uncovered targets around targeted repairs.
    std::expected<std::uint64_t, Error> received(std::string_view id) const;
    /// Private complete-source candidate; final replace rechecks identity and position.
    std::expected<Source::Draft, Error> prepare(std::string_view id, std::uint64_t position);
    /// One Scope per step; existing coverage evidence prevents regression after partial success.
    using Recovery = Restore<State>;
    /// Creates a cancellable private task without installing any Scope. Confirm source position only after all Scopes finish.
    std::expected<Recovery, Error> restore(std::string_view id, Source::Draft&& draft);
    /// Component entry drains synchronously; failure preserves earlier complete Scopes and published views.
    std::expected<void, Error> replace(std::string_view id, Source::Draft&& draft);
    /// Looks up this source's complete value for deadline-only increments; never borrows another source's body.
    std::expected<std::optional<Record>, Error> replica(std::string_view id, const Scope& scope, std::string_view key) const;
    /// Native fact at a strictly contiguous position. Renew without this source's body returns ended for targeted repair.
    std::expected<void, Error> apply(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, Record record, Source::Form form);
    /// Unknown at this source preserves other-source visibility and merged watermarks; covers only target events through R.
    std::expected<void, Error> repair(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, std::optional<Record> record);

private:
    /// Shared clock/directory/accounting mechanisms; State retains all resources.
    friend class Context<State>;
    /// Shared read synchronization without exposing private locks or reclamation types.
    friend class Reading<State>;
    friend class Restore<State>;
    /// Atomically installs one Scope's source/merge/projection/deadlines/coverage without advancing source-wide ACK.
    std::expected<void, Error> install(std::string_view id, const Source::Draft& draft, const Scope& scope);
    /// After every Scope finishes, rechecks source identity and higher coverage before confirming the complete position.
    std::expected<void, Error> finish(std::string_view id, std::uint64_t position);

    /// Stable hook sharing source names, without duplicate deadlines or bodies.
    struct Timer : Agenda::Node {
        /// Names owned by the prepared source.
        explicit Timer(Source::Tree::Key name) : name(std::move(name)) {}

        /// Direct Scope/key lookup on expiration, without scanning the source table.
        Source::Tree::Key name;
    };

    /// Remote source stores only its own facts and TTLs, without history for rebroadcasting third-party facts.
    struct Replica {
        /// Targeted-repair/Scope coverage retained until the contiguous prefix catches up, even after bodies expire.
        struct Coverage {
            /// Shared Scope/key ownership; empty key marks the whole Scope, never a business record.
            Source::Tree::Key name;
            /// Installed R for this target, not source-wide ACK.
            std::uint64_t position{};
        };

        /// Initial source position zero.
        Replica(std::shared_ptr<std::shared_mutex> gate, Source::Limits limits) : source(std::move(gate), static_cast<Source::Measure>(&State::measure), false, limits) {}

        /// Exclusive native-candidate lock. Release domain while waiting; private preparation runs outside domain.
        std::mutex mutex;
        /// Independent native root, without other-source higher versions.
        Source source;
        /// Allocated on first finite body.
        std::unique_ptr<Agenda> agenda;
        /// Stable nodes only for active bodies.
        std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> timers;
        /// At most 128 exact targets plus 2 * source.scopes markers, reclaimed when the contiguous prefix catches up.
        std::vector<Coverage> coverage;
        /// Rejects late tasks after trusted replacement; group can be reclaimed once all bodies expire.
        bool retired{};
    };

    /// Per-source preparation exclusion; local source never acquires a remote-source lock.
    using Guard = Borrowing<Replica>;
    /// Find under domain, release domain while waiting, then recheck directory identity. Null get means unknown source.
    Guard acquire(std::string_view id, std::unique_lock<std::shared_mutex>& domain) const;

    /// Preallocates merged hooks for full-source recovery; rollback removes new hooks without changing existing active ones.
    struct Hooks {
        /// Caller holds the outer domain lock for every operation.
        State& owner;
        /// New unscheduled hook indices.
        std::vector<const Source::Name*> added;
        /// True after the noexcept commit completes.
        bool committed{};
        /// Removes all new nodes on failure.
        ~Hooks();
        /// Reuses existing nodes and registers rollback before adding new ones.
        void add(const Source::Tree::Key& name);
    };

    /// Releases old content/history and detached hooks outside domain after commit, avoiding bulk reclamation under lock.
    struct Retired {
        /// Detached merged-deadline nodes, reclaimed independently of source timers.
        std::unique_ptr<Timer> deadline;
        /// Old merged watermark/content references, reclaimed independently of local source.
        Source::Retired merged;
        /// Overwritten/deleted source values and evicted source history.
        Source::Retired source;
        /// Visible notifications and evicted projection history; empty without visible changes.
        Projection::Retired scene;
        /// Detached nodes; none may remain linked into a wheel outside domain.
        std::unique_ptr<Timer> timer;
    };

    /// Rolls back new directories/hooks on preparation failure; source/projection Edits own their own candidate rollback.
    struct Pending {
        /// One domain lock covers preparation lifetime.
        State& owner;
        /// Borrows request addresses during the synchronous call.
        const Scope& scope;
        /// Temporary unscheduled hook index.
        const Source::Name* timer{};
        /// New merged-deadline hook, removed from scheduling on abandonment.
        const Source::Name* deadline{};
        /// Whether this preparation created an unpublished empty Scope.
        bool created{};
        /// Complete commit disables rollback.
        bool committed{};
        /// Remove hooks before deleting the unpublished Scope.
        ~Pending();
    };

    /// At most 1 MiB per body; watermarks have zero payload cost. Source/projection account for metadata separately.
    static std::size_t measure(const Record& record) noexcept;
    /// Count visible payload bytes; a watermark without a payload contributes zero.
    static std::size_t measure(const Content& record) noexcept;
    /// Maps native/source/projection failures without inferring commit effect from diagnostic text.
    static Error error(Catalog::Error error) noexcept;
    /// Map source preparation or history failures into this domain's stable error categories.
    static Error error(Source::Error error) noexcept;
    /// Map visible-projection failures into this domain's stable error categories.
    static Error error(Projection::Error error) noexcept;
    /// Final time must be established and nondecreasing; absent reading returns clock.
    std::expected<Clock::Reading, Error> reading();
    /// Internal expected<T, Error> read: shared before a full-tick boundary, exclusive only when advancement is needed. Action must not reenter State or return protected raw borrows.
    /// Preparation, reads, and unwinding unlock domain before reclaiming old resources. Instantiated only here; does not wrap final write-time sampling.
    auto execute(auto&& action);
    /// Creates bounded Scopes only for writes/replica installation and retains committed cursors; reads use locate.
    std::expected<Projection*, Error> obtain(const Scope& scope);
    /// Shared remaining history allowance, reusing the current Scope's existing allowance for replacement.
    std::size_t allowance(const Projection& scene) const;
    /// Accounts/notifies prepared visible commits without network or application callbacks.
    void publish(Projection& scene, std::size_t before, const Projection::Event& event) noexcept;
    /// Held is already exclusively owned by the caller and advances separately. Returns busy sources with expiration/retirement work for waiting outside domain.
    /// Tick callbacks expire only actual deadlines; intermediate wakeups reschedule from the current tick.
    std::shared_ptr<Replica> advance(Clock::Time now, std::vector<Retired>& retired, Replica* held = nullptr);
    /// Remote expiration releases bodies and retains source watermarks, without local-source increments.
    void advance(Replica& replica, Clock::Time now, std::vector<Retired>& retired);
    /// Shared atomic preparation boundary for contiguous increments and targeted repair.
    std::expected<void, Error> receive(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, std::optional<Record> record, Source::Form form, bool repair);
    /// Lookup without Scope allocation, used by full-group recovery to inspect published content.
    Projection* locate(const Scope& scope);
    /// Expires bodies/projections while retaining positive source watermarks, without advancing source position or broadcast history.
    std::expected<Retired, Error> expire(const Scope& scope, std::string_view key, Clock::Time time, bool projected);
    /// Shared prepare/resample/commit boundary for direct writes; renewal accepts no body.
    std::expected<void, Error> change(const Scope& scope, std::string_view key, Value value, std::uint64_t version, std::uint32_t ttl, bool renewal);

    /// Exclusive for writes/merge commits; shared for public reads needing no expiration work.
    const std::shared_ptr<std::shared_mutex> gate_ = std::make_shared<std::shared_mutex>();
    /// Local root/history synchronization; lock order gate_ -> export_. Source export never acquires gate_.
    const std::shared_ptr<std::shared_mutex> export_ = std::make_shared<std::shared_mutex>();
    /// Serializes only injected-clock sampling and monotonic checks, leaving body capture independent among readers.
    std::mutex timing_;
    /// Earliest wheel boundary; zero forces recheck and max means no wheel. Not a second per-record deadline.
    Clock::Time due_{};
    /// Final-acceptance time provider; callers cannot supply stale Readings.
    Time time_;
    /// Fixed source/Scope/downstream limits.
    const Limits limits_;
    /// This Star's Catalog source, with one position across Scopes.
    Source source_;
    /// Bounded admitted remote sources only.
    std::map<std::string, std::shared_ptr<Replica>, std::less<>> replicas_;
    /// Current logical remote row/directory bytes.
    std::size_t replicaBytes_{};
    /// Highest cross-source versions and longest valid deadlines; unsequenced, never broadcast, and not a local-source export.
    Source merged_;
    /// Merged-visible deadline wheel, independent of local-source deadlines.
    std::unique_ptr<Agenda> outlook_;
    /// Merged deadline hooks sharing public-projection keys.
    std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> deadlines_;
    /// Stable source wheel allocated only for the first finite deadline.
    std::unique_ptr<Agenda> agenda_;
    /// Hook lookup by stable shared name pointer, without a second key copy.
    std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> timers_;
    /// Sector/Spectrum visibility directory; empty Scopes retain cursors.
    std::map<std::string, std::map<std::string, Projection, std::less<>>, std::less<>> scenes_;
    /// Number of established projection Scopes.
    std::size_t scopes_{};
    /// Total logical Scene history bytes.
    std::size_t history_{};
    /// Rejects injected-clock regression; not another record deadline.
    std::optional<Clock::Time> observed_;
    /// Internal commit notification, initially disabled.
    Notify notify_{};
    /// Context associated with notify_, initially null.
    void* context_{};
};
} // namespace astra
