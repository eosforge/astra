// Coordinate Ephemeris ownership, replicated sources, quotas, and lifetime scheduling.
#pragma once
#include "agenda.hpp"
#include "borrowing.hpp"
#include "context.hpp"
#include "ephemeris.hpp"
#include "origin.hpp"
#include "reading.hpp"
#include "restore.hpp"
#include "scene.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace astra {
/// Commits one Star's local Ephemeris, ordering native state, source history, content projection, and one source-level deadline wheel.
/// RPC callers validate Session/instance and retain Access::Permit until return. State calls no application callbacks or network operations.
class Ephemeris::State {
public:
    /// One source position covers this Star's Ephemeris Scopes.
    using Source = Origin<Record, true>;

    /// Public projection excludes TTL/orders. Renew and same-byte Update create no page copy or observation event.
    struct Content {
        /// Immutable native attributes.
        Value attr;
        /// Current immutable native Data, including valid empty bytes.
        Value data;
    };

    /// Names/Attr/Data shared with source, without paired keys.
    using Projection = Scene<Content, Source::Name>;
    /// Sampled under the final commit lock; production uses the real Clock.
    using Time = std::move_only_function<std::optional<Clock::Reading>()>;
    /// Bounded internal collector, without external user callbacks.
    using Notify = void (*)(void*, const Scope&, const Projection::Event&) noexcept;

    /// Separates business rejection from capacity/history errors. RPC maps allocation exceptions to resource exhaustion.
    enum class Error {
        /// Invalid input, Scope, UUID, payload, or order.
        Input,
        /// No usable local application time, distinct from temporary Pulsar disconnection.
        Clock,
        /// Local UUID is missing or expired; Update/Renew cannot revive it.
        Ended,
        /// Order below the confirmed value.
        Obsolete,
        /// Same order with different Data, or bounded random retries still collide.
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
        /// Remote-source count limit, independent of Scope count.
        std::size_t replicas = 63;
        /// Total logical budget for native remote sources in this domain.
        std::size_t replicaBytes = 128 * 1024 * 1024;
    };

    /// Create receipt includes identity, fixed TTL, and adopted Data order, without internal scheduling nodes.
    struct Receipt {
        /// Newly issued or verified recovered logical UUID, raw 16 bytes, owned by the successful caller.
        std::string uuid;
        /// Actual recovered data, possibly newer than the caller's version.
        Value data;
        /// Actual Data order; recovery fabricates no increment.
        std::uint64_t order{};
        /// Local registration generation.
        std::uint64_t generation{};
        /// Fixed registration TTL, 1000..600000 milliseconds.
        std::uint32_t ttl{};
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
    /// Creates or recovers UUID from final usable time. Failure leaves no record, wheel node, or source position behind.
    std::expected<Receipt, Error> create(const Scope& scope, Value attr, Value data, std::uint32_t ttl, std::string uuid = {}, std::uint64_t generation = 0, std::uint64_t order = 0, std::string_view capability = {});
    /// Updates an existing local UUID, rechecking deadline after preparation. A new order atomically replaces Data and extends fixed TTL.
    std::expected<void, Error> update(const Scope& scope, std::string_view uuid, Value data, std::uint64_t order, std::uint64_t generation = 0, std::string_view capability = {});
    /// New Renew order extends fixed TTL; same order confirms without advancing source position or deadline.
    std::expected<void, Error> renew(const Scope& scope, std::string_view uuid, std::uint64_t order, std::uint64_t generation = 0, std::string_view capability = {});
    /// Explicit authoritative termination; ended records return ended. Deletion, source history, and visibility publish together.
    std::expected<void, Error> remove(const Scope& scope, std::string_view uuid, std::uint64_t generation = 0, std::string_view capability = {});
    /// Advances all elapsed full ticks. Failure propagates without claiming catch-up; earlier complete expirations remain committed.
    void tick();
    /// Advances expiration then captures one public Scope. Missing Scopes return an empty root at cursor zero without directory allocation.
    std::expected<Projection::View, Error> capture(const Scope& scope);
    /// Exact lookup after expiration, without a table snapshot; returns explicit absence and Scope cursor.
    std::expected<Projection::Point, Error> find(const Scope& scope, std::string_view uuid);
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
    /// Verified peer control only: admits a Star process ID without authenticating or readmitting a superseded identity.
    std::expected<void, Error> admit(std::string_view id);
    /// Freezes the old source only after verified same-deployment replacement; existing data retains its original TTL.
    void retire(std::string_view id);
    /// Remote contiguous installed position. Unknown source returns input; targeted repair is not a group position.
    std::expected<std::uint64_t, Error> received(std::string_view id) const;
    /// Private source baseline without installation; final replace rechecks position/current deadlines.
    std::expected<Source::Draft, Error> prepare(std::string_view id, std::uint64_t position);
    /// Installs at most one Scope per advance, without retaining domain across calls.
    using Recovery = Restore<State>;
    /// Converts a complete candidate to staged recovery; source confirmation waits for every Scope.
    std::expected<Recovery, Error> restore(std::string_view id, Source::Draft&& draft);
    /// Drains staged recovery synchronously; failure preserves installed-Scope coverage and published data.
    std::expected<void, Error> replace(std::string_view id, Source::Draft&& draft);
    /// Looks up complete replicas for Data/Renew adaptation. Missing records require repair; grants no local-write authority.
    std::expected<std::optional<Record>, Error> replica(std::string_view id, const Scope& scope, std::string_view uuid) const;
    /// Contiguous complete source fact preserving Data/Renew form; missing records return ended for targeted repair.
    std::expected<void, Error> apply(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record, Source::Form form);
    /// Repairs only this target through position, without advancing source-wide ACK. Stream control verifies request correlation.
    std::expected<void, Error> repair(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record);

private:
    /// Shared clock/directory/accounting mechanisms; State retains all resources.
    friend class Context<State>;
    /// Shared read synchronization without exposing private locks or reclamation types.
    friend class Reading<State>;
    friend class Restore<State>;
    /// Atomically installs one Scope's native state, visible projection, and timers without early source-wide confirmation.
    std::expected<void, Error> install(std::string_view id, const Source::Draft& draft, const Scope& scope);
    /// After every Scope completes, advances source position and reclaims temporary coverage evidence.
    std::expected<void, Error> finish(std::string_view id, std::uint64_t position);

    /// Stable hook sharing source names, without duplicate deadline/Attr/Data.
    struct Timer : Agenda::Node {
        /// Names owned by the prepared source.
        explicit Timer(Source::Tree::Key name) : name(std::move(name)) {}

        /// Direct Scope/UUID lookup on expiration, without source-table scans.
        Source::Tree::Key name;
    };

    /// Independent remote-Star source/scheduler, without history for third-party rebroadcast.
    struct Replica {
        /// Temporary targeted/Scope coverage until the contiguous prefix catches up, not a permanent side table for every UUID.
        struct Coverage {
            /// Shared address/UUID ownership; empty key means whole Scope. Correlation survives body expiration/deletion.
            Source::Tree::Key name;
            /// Installed target/Scope position, distinct from the group's contiguous position.
            std::uint64_t position{};
        };

        /// Initial source position zero.
        Replica(std::shared_ptr<std::shared_mutex> gate, Source::Limits limits) : source(std::move(gate), static_cast<Source::Measure>(&State::measure), false, limits) {}

        /// Exclusive native-candidate lock. Release domain while waiting; private preparation runs outside domain.
        std::mutex mutex;
        /// This Star's Scopes, with independent sequencing from other sources.
        Source source;
        /// Continues advancing original deadlines after disconnection.
        std::unique_ptr<Agenda> agenda;
        /// Stable hooks sharing names.
        std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> timers;
        /// At most 128 exact targets plus 2 * source.scopes markers, committed with bodies.
        std::vector<Coverage> coverage;
        /// Trusted replacement rejects new facts; reclaim empty groups while control retains old-identity rejection evidence.
        bool retired{};
    };

    /// Per-source preparation exclusion; local source never acquires a remote-source lock.
    using Guard = Borrowing<Replica>;
    /// Find under domain, release domain while waiting, then recheck directory identity. Null get means unknown source.
    Guard acquire(std::string_view id, std::unique_lock<std::shared_mutex>& domain) const;

    /// Bounded source contributions per logical ID, supporting safe merges while native preparation runs outside domain.
    struct Contribution {
        /// Shares native names/payloads without reading a source tree under preparation.
        Source::Tree::Key name;
        /// Complete source fact with original absolute deadline.
        Record record;
        /// Null denotes local source; remote directory outlives its final hook.
        const Replica* owner{};
    };

    /// Order candidates by logical Scope and UUID bytes, independently of shared-pointer identity.
    struct Compare {
        /// Compare logical Scope and UUID bytes, without depending on shared-pointer identity.
        bool operator()(const Source::Tree::Key& left, const Source::Tree::Key& right) const {
            return *left->scope != *right->scope ? *left->scope < *right->scope : left->key < right->key;
        }
    };

    /// One candidate set per logical Scope/UUID, independent of name-pointer identity.
    using Choices = std::map<Source::Tree::Key, std::vector<Contribution>, Compare>;

    /// Private candidate preparation; existing rows stay unchanged until atomic commit.
    struct Choice {
        /// Rollback owner; moving transfers responsibility under the domain lock.
        State* owner;
        /// Stable map position for this logical Scope/UUID.
        Choices::iterator position;
        /// General-path replacement set; takes the old set after commit.
        std::vector<Contribution> rows;
        /// Selected name, or the stable deletion name; retains the old name after a single commit.
        Source::Tree::Key name;
        /// Selected record; a single replacement is staged here until commit.
        std::optional<Record> record;
        /// Only visible Attr/Data changes advance the projection cursor.
        bool changed{};
        /// A newly inserted empty map node must be removed on rollback.
        bool created{};
        /// An active same-source replacement of one existing row, with no rows allocation.
        bool single{};
        /// Prepare privately; the domain lock covers preparation through commit or rollback.
        Choice(State& owner, Choices::iterator position, std::vector<Contribution> rows, Source::Tree::Key name, std::optional<Record> record, bool changed, bool created, bool single);
        /// Transfer rollback responsibility without allocating.
        Choice(Choice&& other) noexcept;
        /// Keep one owner of candidate publication and rollback responsibility; copying is forbidden.
        Choice(const Choice&) = delete;
        /// An abandoned preparation only removes its newly inserted empty node.
        ~Choice();
        /// Revise the local candidate after final-time validation, before commit.
        void revise(const Record& replacement) noexcept;
        /// Swap only after all source/projection preparation succeeds; retain old references.
        void commit() noexcept;

        /// Share immutable selected content for projection preparation.
        std::optional<Content> content() const {
            return record ? std::optional(Content{record->attr, record->data}) : std::nullopt;
        }
    };

    /// Prepares one logical ID's replacement set under domain, without entering other-source locks.
    std::expected<Choice, Error> choose(const Source::Tree::Key& name, std::optional<Record> record, const Replica* owner, Clock::Time now);

    /// Releases old content/history and detached hooks outside domain after commit, avoiding bulk reclamation under lock.
    struct Retired {
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
        /// Whether this preparation created an unpublished empty Scope.
        bool created{};
        /// Complete commit disables rollback.
        bool committed{};
        /// Remove hooks before deleting the unpublished Scope.
        ~Pending();
    };

    /// Shares two native payload references only, each bounded to 1 MiB.
    static std::size_t measure(const Record& record) noexcept;
    /// Count both complete Attr and Data payloads in visible-content accounting.
    static std::size_t measure(const Content& record) noexcept;
    /// Maps native/source/projection failures without inferring commit effect from diagnostic text.
    static Error error(Ephemeris::Error error) noexcept;
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
    /// Replica expiration changes no source position/local broadcast; only removes the corresponding visible registration.
    void advance(Replica& replica, Clock::Time now, std::vector<Retired>& retired);
    /// Lookup without Scope creation, for source installation/local-expiration visibility checks.
    Projection* locate(const Scope& scope);
    /// Atomic preparation shared by contiguous facts and targeted repair. repair=true records target coverage without advancing source position.
    std::expected<void, Error> receive(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record, Source::Form form, bool repair);
    /// Prepares source/projection deletion together; detach, publish, and reclaim only after every fallible step succeeds.
    std::expected<Retired, Error> erase(const Scope& scope, std::string_view uuid, std::chrono::steady_clock::time_point now, bool active = false);
    /// Update/Renew share two-stage commit. Renew accepts no Data; application orders remain independent.
    std::expected<void, Error> change(const Scope& scope, std::string_view uuid, Value data, std::uint64_t order, bool renewal, std::uint64_t generation, std::string_view capability);

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
    /// This Star's Ephemeris source, with one position across Scopes.
    Source source_;
    /// Remote groups bounded by count and total bytes.
    std::map<std::string, std::shared_ptr<Replica>, std::less<>> replicas_;
    /// Local/remote contributions by logical ID, supporting merge selection and expiration fallback.
    Choices choices_;
    /// Current remote row/directory cost, without third-party send history.
    std::size_t replicaBytes_{};
    /// Stable source wheel allocated only for the first finite deadline.
    std::unique_ptr<Agenda> agenda_;
    /// Hook lookup by stable shared name pointer without UUID formatting.
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
