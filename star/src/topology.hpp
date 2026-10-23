// Role-bounded Star topology and generation-aware session ownership.
#pragma once
#include <astra/policy.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace astra {
/// Star topology policy, owning known admitted members and one active Star stream's direction/generation.
/// Mutex protects only memory. Caller cancels/closes returned I/O resources outside the lock.
class Star final : public Policy {
public:
    /// Copies network capacity/backoff configuration. Initially uninitialized and starts no dial.
    explicit Star(const Config& config);

    /// Installs a verified local identity and complete Star directory once, checking order, uniqueness, and exact local presence.
    /// Success returns empty. Capacity returns capacity; malformed identity/order returns identity; repeated initialization returns conflict. Failure preserves state.
    Result<void> initialize(const Member& local, std::span<const Member> members) override;
    /// Merges a complete trusted Star directory without removing omitted members or regressing epochs; equal-epoch conflict rejects the whole batch.
    Result<std::vector<Generation>> refresh(const Member& local, std::span<const Member> members) override;

    /// Accepts a verified peer under Policy's contract. Outbound remote must match expected; Planet is inbound only.
    /// Installs generation in the sole active slot. Direction competition and newer member epochs return obsolete generations for off-lock cancellation.
    /// Returns cancelled generations on success, or identity/conflict/capacity errors.
    Result<std::vector<Generation>> accept(const Member& remote, Policy::Direction direction, Generation generation, const std::optional<Member>& expected) override;

    /// Closes only the matching generation, then adjusts backoff from monotonic now and connection stability for either direction.
    /// Admitted members remain eligible for backoff retries regardless of error; no quarantine, membership removal, or consensus here.
    void closed(Generation generation, std::optional<Status::Code> error, Steady::time_point now) override;

    /// Returns one due Star snapshot without any accepted stream and marks it pending, preventing duplicate selection.
    std::optional<Member> due(Steady::time_point now) override;

    /// Only a full matching target releases pending and updates retry time; error does not quarantine Star members.
    void failed(const Member& target, Status::Code error, Steady::time_point now) override;

    /// Periodic refresh polling always returns false; verified handshakes admit new identities, and explicit refresh merges trusted directories.
    bool needsRefresh(Steady::time_point now) override;

    /// Owned installed-session counter snapshot under mutex_. Star inbound+outbound is at most members minus one; half-open handshakes are excluded.
    Policy::State status() const override;

private:
    /// Runtime connection state for one known member.
    struct Entry {
        /// Member identity/address metadata.
        Member member;

        /// At most one occupied slot: 0=outbound, 1=inbound, matching Policy::Direction order. Runtime retains pending candidates separately.
        std::array<std::optional<Generation>, 2> sessions{};

        /// Outbound dial pending, initially false.
        bool pending{};
        /// Consecutive outbound failure count, initially zero.
        std::uint32_t failures{};
        /// Next retry time, initially monotonic epoch zero.
        Steady::time_point next{};
        /// Current stream establishment time for stability checks, initially epoch zero.
        Steady::time_point connected{};
    };

    /// Owned network limits and retry configuration.
    Config config_;
    /// Memory-state synchronization only.
    mutable std::mutex mutex_;
    /// Local identity, absent before initialization.
    std::optional<Member> local_;

    /// Principal-ordered member map gives deterministic dial traversal within configured capacity.
    /// Never deep-copy the map on heartbeat hot paths.
    std::map<Principal, Entry> members_;
};

/// Creates an uninitialized Star policy from validated configuration; Runtime takes ownership without a long-lived config borrow.
std::unique_ptr<Policy> makeStar(const Config& config);
} // namespace astra
