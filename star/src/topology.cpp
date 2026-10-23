// Maintain Star topology and session generations; mutex_ protects memory only, never blocking I/O or external-resource reclamation.
#include "topology.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <ranges>
#include <type_traits>
#include <vector>

namespace astra {

Star::Star(const Config& config) : config_(config) {}

Result<std::vector<Generation>> Star::refresh(const Member& local, std::span<const Member> members) {

    // Reuse complete-directory validation without networking or changing current sessions.
    Star candidate(config_);
    if (auto initialized = candidate.initialize(local, members); !initialized) {
        return std::unexpected(initialized.error());
    }
    const std::lock_guard lock(mutex_); // Merge directory and verified handshakes at the same identity boundary.
    if (!local_ || *local_ != local) {
        return Status::identity("Directory replaced local process");
    }
    auto prepared = members_; // Low-frequency control-plane copy preserves sessions/backoff; all fallible allocations precede final swap.
    std::vector<Generation> cancelled;
    for (auto& [principal, incoming] : candidate.members_) {
        const auto old = prepared.find(principal);
        if (old == prepared.end()) {
            prepared.emplace(principal, std::move(incoming));
            continue;
        }
        if (incoming.member.epoch < old->second.member.epoch) {
            continue;
        }
        const auto replace = supersedes(incoming.member, old->second.member);
        if (!replace) {
            return std::unexpected(replace.error());
        }
        if (*replace) {
            for (const auto generation : old->second.sessions) {
                if (generation) {
                    cancelled.push_back(*generation);
                }
            }
            old->second = std::move(incoming);
        }
    }

    // Omitted old members still reserve identity/address, so alias checks must cover the merged directory.
    std::map<Id, Principal> ids;
    std::map<Endpoint, Principal> addresses;
    std::size_t stars = 1; // Includes this process; Planet retains a separate role quota.
    for (const auto& [principal, entry] : prepared) {
        if (entry.member.role == Member::Role::Star) {
            ++stars;
        }
        if (entry.member.id == local.id || entry.member.address == local.address || !ids.emplace(entry.member.id, principal).second || !addresses.emplace(entry.member.address, principal).second) {
            return Status::identity("Merged directory aliases existing member");
        }
    }
    if (stars > config_.maxMembers) {
        return Status::capacity("Merged Star directory exceeds capacity");
    }
    members_.swap(prepared);
    return cancelled;
}

Result<void> Star::initialize(const Member& local, std::span<const Member> members) {

    if (members.empty() || members.size() > config_.maxMembers) {
        return Status::capacity("Invalid complete Star list size");
    }

    // Prepare privately; validation/allocation failure preserves installed state.

    std::map<Principal, Entry> prepared;
    // Previous ID borrows the input list only during this call.
    std::optional<std::string_view> previous;
    bool found = false;

    for (const auto& member : members) {
        // Require valid same-Galaxy Stars in strictly increasing ID order, including the exact local identity.

        if (!member.validate() || member.galaxy != config_.galaxy || member.role != Member::Role::Star || (previous && *previous >= member.id)) {
            return Status::identity("Invalid complete Star list");
        }
        previous = member.id;

        if (member.principal == local.principal) {

            if (member != local) {
                return Status::identity("Complete list conflicts with local identity");
            }
            found = true;
        } else {

            if (!prepared.emplace(member.principal, Entry{.member = member}).second) {
                return Status::identity("Duplicate principal in complete Star list");
            }
        }
    }

    if (!found) {
        return Status::identity("Complete list omits local identity");
    }

    // Principals are already unique; strict ID order/full local comparison also reject duplicate local identity.

    // Reject distinct members sharing an endpoint.
    auto addresses = members | std::views::transform([](const Member& m) { return m.address.text(); }) | std::ranges::to<std::vector>();
    std::ranges::sort(addresses);
    if (std::ranges::adjacent_find(addresses) != addresses.end()) {
        return Status::identity("Duplicate address in complete Star list");
    }

    // Own local identity before commit so string allocation cannot leave a directory-only initialization.
    std::optional<Member> identity{local};
    static_assert(std::is_nothrow_move_assignable_v<decltype(identity)>);

    std::lock_guard lock(mutex_);

    if (local_) {
        return Status::conflict("Star topology already initialized");
    }

    // Publish both prepared states without allocation.
    members_.swap(prepared);
    local_ = std::move(identity);
    return {};
}

Result<std::vector<Generation>> Star::accept(const Member& remote, Policy::Direction direction, Generation generation, const std::optional<Member>& expected) {

    // Protect topology memory only; Runtime performs returned network actions after unlock.
    std::lock_guard lock(mutex_);

    // Accept Star or inbound Planet in the same Galaxy, excluding local ID/principal/address and control-plane roles.

    if (!local_ || (remote.role != Member::Role::Star && remote.role != Member::Role::Planet) || remote.galaxy != local_->galaxy || remote.id == local_->id || remote.principal == local_->principal || remote.address == local_->address || (remote.role == Member::Role::Planet && direction != Policy::Direction::Inbound)) {
        return Status::identity("Invalid star relationship");
    }

    // An expected outbound target must match the complete verified identity.
    if (expected && (remote != *expected || direction != Policy::Direction::Outbound)) {
        return Status::identity("Dial target identity changed");
    }

    // Different principals cannot reuse an existing member's ID or address.
    for (const auto& [principal, entry] : members_) {
        if (principal != remote.principal && (entry.member.id == remote.id || entry.member.address == remote.address)) {
            return Status::conflict("Member aliases an existing identity");
        }
    }

    auto existing = members_.find(remote.principal);
    std::vector<Generation> cancelled; // Old session generations to cancel outside the lock.

    if (existing == members_.end()) {

        const auto count = std::count_if(members_.begin(), members_.end(), [&](const auto& pair) { return pair.second.member.role == remote.role; });
        // Star capacity includes this process; subtract its slot only for the Star role.
        const auto maximum = config_.maxMembers - (remote.role == Member::Role::Star ? 1U : 0U);
        if (static_cast<std::size_t>(count) >= maximum) {
            return Status::capacity("Member capacity reached");
        }

        existing = members_.emplace(remote.principal, Entry{.member = remote}).first;
    } else {

        auto replace = supersedes(remote, existing->second.member);
        if (!replace) {
            return std::unexpected(replace.error());
        }
        if (*replace) {

            // A newer member epoch retires all active old sessions before replacement.
            for (auto session : existing->second.sessions) {
                if (session) {
                    cancelled.push_back(*session);
                }
            }

            existing->second = Entry{.member = remote};
        }
    }

    // Resolve duplicate streams only after identity checks: same direction cannot preempt; opposite directions use initiator-ID order.
    auto& entry = existing->second;
    const auto index = static_cast<std::size_t>(direction);
    auto& slot = entry.sessions[index];
    auto& opposite = entry.sessions[1 - index];
    if (slot) {
        return Status::conflict("Star session initiator is already active");
    }
    if (remote.role == Member::Role::Star && opposite) {
        const auto& candidate = direction == Policy::Direction::Outbound ? local_->id : remote.id;
        const auto& current = direction == Policy::Direction::Outbound ? remote.id : local_->id;
        const bool preferred = std::lexicographical_compare(candidate.begin(), candidate.end(), current.begin(), current.end(), [](char left, char right) { return static_cast<unsigned char>(left) < static_cast<unsigned char>(right); });
        if (!preferred) {
            return Status::conflict("Opposite Star session has the preferred initiator");
        }
        cancelled.push_back(*opposite); // Finish allocation before noexcept transfer of the sole active slot.
        opposite.reset();
    }
    slot = generation;
    if (direction == Policy::Direction::Outbound) {
        entry.pending = false;
    }
    entry.connected = Steady::now(); // Either direction contributes stability time and permits redial after closure.
    return cancelled;
}

void Star::closed(Generation generation, std::optional<Status::Code>, Steady::time_point now) {

    std::lock_guard lock(mutex_);
    for (auto& [principal, entry] : members_) {
        for (std::size_t index = 0; index < entry.sessions.size(); ++index) {

            if (entry.sessions[index] == generation) {

                entry.sessions[index].reset();
                // Only the current generation triggers redial; losing old streams cannot clear the replacement slot.
                entry.failures = now - entry.connected >= config_.stableConnection ? 1 : std::min(entry.failures + 1, 100U);
                entry.next = now + retryDelay(entry.failures, config_, principal.bytes[0] + std::hash<Id>{}(local_->id));
                return;
            }
        }
    }
}

std::optional<Member> Star::due(Steady::time_point now) {

    std::lock_guard lock(mutex_);
    if (local_) {
        for (auto& [principal, entry] : members_) {
            // Dial only nonpending Stars with no accepted stream in either direction, after backoff expires.

            if (entry.member.role == Member::Role::Star && !entry.pending && !entry.sessions[0] && !entry.sessions[1] && now >= entry.next) {
                // Copy target successfully before setting pending, preventing allocation failure from stranding a dial reservation.
                auto target = entry.member;

                entry.pending = true;
                return target;
            }
        }
    }
    return std::nullopt;
}

void Star::failed(const Member& target, Status::Code, Steady::time_point now) {

    std::lock_guard lock(mutex_);
    // Match the full failed target snapshot before modifying backoff.
    const auto found = members_.find(target.principal);

    if (found != members_.end() && found->second.member == target) {

        auto& entry = found->second;
        entry.pending = false;
        if (entry.sessions[0] || entry.sessions[1]) {
            return; // Failure of a duplicate dial cannot mark an already accepted healthy stream disconnected or unstable.
        }

        entry.failures = std::min(entry.failures + 1, 100U);
        entry.next = now + retryDelay(entry.failures, config_, target.principal.bytes[0] + std::hash<Id>{}(local_->id));
    }
}

bool Star::needsRefresh(Steady::time_point) {
    // Periodic policy polling does not request a directory refresh.
    return false;
}

Policy::State Star::status() const {

    std::lock_guard lock(mutex_);
    // Return an owned counter snapshot under mutex_, without member-table borrows.
    Policy::State result;
    result.initialized = local_.has_value();
    result.members = local_ ? 1 : 0;

    for (const auto& [principal, entry] : members_) {
        if (entry.member.role == Member::Role::Star) {
            ++result.members;
            result.outbound += entry.sessions[0].has_value();
            result.inbound += entry.sessions[1].has_value();
        } else {

            result.planetInbound += entry.sessions[1].has_value();
        }
    }
    return result;
}

std::unique_ptr<Policy> makeStar(const Config& config) {
    return std::make_unique<Star>(config);
}
} // namespace astra
