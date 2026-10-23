// Role-policy contracts separate network transport from topology state.
#pragma once
#include <astra/config.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace astra {

/// Shared Star/Planet lifecycle interface. Implementations own their indexes, perform no gRPC calls, and invoke no external code under locks.
class Policy {
public:
    /// Direction indexes match the two-way Session array: outbound 0, inbound 1.
    enum class Direction {
        /// Locally initiated Session, index 0 and the value-initialized default.
        Outbound,
        /// Accepted remote Session, index 1. Star shares one active Session across directions; Planet retains its existing upstream direction.
        Inbound
    };

    /// Consistent current-index diagnostics, not accumulated lossy events or business synchronization status.
    struct State {
        /// Local role identity and initial directory installed; says nothing about Registry/Catalog synchronization.
        bool initialized{};

        /// Known Star members including self; unused by Planet.
        std::size_t members{};

        /// Installed inbound Star Sessions, excluding incomplete connections and TLS handshakes.
        std::size_t inbound{};

        /// Installed outbound Star Sessions; for Planet, active upstream connection count.
        std::size_t outbound{};

        /// Installed inbound Planet Sessions, counted separately from Star inbound for isolation and capacity limits.
        std::size_t planetInbound{};

        /// Planet upstream candidates, including backoff and quarantined entries; not a healthy-connection count.
        std::size_t candidates{};

        /// Independent snapshot of Planet's active upstream Member; nullopt when disconnected or not attached.
        std::optional<Member> activeMember;
    };

    /// Releases policy memory only. Stop all advancement before destruction; this does not cancel live RPCs.
    virtual ~Policy() = default;

    /// Validates the entire directory before atomic installation. local is admission-validated; members is borrowed and required values are copied.
    /// Identity, capacity, and duplicate-installation conflicts return Status. Failed Planet refresh preserves valid candidates.
    virtual Result<void> initialize(const Member& local, std::span<const Member> members) = 0;

    /// Trusted Star directory refresh preserves observed newer identities and omitted members; returns old Sessions to cancel outside locks.
    /// Rejected by default; frozen Planet retains its candidate flow without business synchronization.
    virtual Result<std::vector<Generation>> refresh(const Member&, std::span<const Member>) {
        return Status::protocol("Role does not support directory refresh");
    }

    /// Validates and installs a signed remote Member, returning old generation IDs for caller-side cancellation outside locks.
    /// direction selects inbound/outbound; generation is unique for the lifecycle; expected is the original outbound target, nullopt for inbound.
    /// Validation failure installs nothing. Success requires retaining the new Session until completion and canceling every returned old generation.
    virtual Result<std::vector<Generation>> accept(const Member& remote, Policy::Direction direction, Generation generation, const std::optional<Member>& expected) = 0;

    /// Removes only the installed generation after completion, so late old events cannot remove a newer Session.
    /// Failure affects retry backoff and Planet quarantine. error empty means ordinary transport closure; now is steady-clock time.
    virtual void closed(Generation generation, std::optional<Status::Code> error, Steady::time_point now) = 0;

    /// Returns at most one pending or retry-due Member at monotonic now, marking it pending atomically to prevent duplicate dialing.
    virtual std::optional<Member> due(Steady::time_point now) = 0;

    /// Reports failure before remote identity is known. target is the due snapshot; error selects bounded backoff or quarantine at monotonic now.
    /// Releases matching pending ownership; stale targets cannot clear a newer active target.
    virtual void failed(const Member& target, Status::Code error, Steady::time_point now) = 0;

    /// Consumes a Planet candidate-refresh request only when all upstreams are exhausted; healthy connections do not trigger extra refreshes.
    /// Uses monotonic now and advances the earliest next refresh time; this is a stateful operation, not a pure query.
    virtual bool needsRefresh(Steady::time_point now) = 0;

    /// Returns a consistent independent network-state snapshot without internal container pointers or references.
    virtual Policy::State status() const = 0;
};

/// Creates the Config-selected concrete policy, such as Star or PlanetUpstream.
using PolicyFactory = std::unique_ptr<Policy> (*)(const Config&);

/// Checks replacement of prevalidated current by candidate: one deployment cannot change role or endpoint; equal epochs require equal key fields.
/// Identity changes, epoch regression, and equal-epoch conflicts reject replacement with conflict.
Result<bool> supersedes(const Member& candidate, const Member& current);

/// Returns jittered reconnect delay within configured bounds, including at the cap; failures zero uses the first-failure base.
/// Requires 0 < reconnectMin <= reconnectMax. salt provides stable desynchronization, never security randomness; wall time is not a random source.
Milliseconds retryDelay(std::uint32_t failures, const Config& config, std::uint64_t salt);

} // namespace astra
