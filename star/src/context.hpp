// Share clock checks, projection lookup, and history configuration without owning domain commit policy.
#pragma once
#include <astra/clock.hpp>
#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <cstddef>
#include <expected>
#include <mutex>

namespace astra {
/// Shared clock checks, projection directory, and history accounting for both dynamic domains; each concrete State retains its data,
/// locks, destruction order, source commits, expiration advancement, and Pending/Retired rollback.
template <typename State>
class Context {
    /// Internal mechanisms accessible only to the owning State, without public directory/accounting APIs.
    friend State;
    /// Composition errors including clock/input/capacity.
    using Error = typename State::Error;
    /// Domain-specific visible content, without body conversion or copying.
    using Projection = typename State::Projection;

    /// Caller holds State's domain lock; timing_ serializes sampling and monotonic checks among shared readers.
    /// Invalid readings preserve observed_. Sampling exceptions propagate while RAII releases timing_.
    static std::expected<Clock::Reading, Error> reading(State& state) {

        ASTRA_PROFILE_BEGIN(waiting, "star.context.reading.wait.timing");
        const std::lock_guard timing(state.timing_);
        ASTRA_PROFILE_END(waiting);
        auto value = state.time_(); // Sample and validate in one critical section, never using caller-presampled time.
        if (!value || !value->ready || value->time.time_since_epoch().count() < 0 || (state.observed_ && value->time < *state.observed_)) {
            return std::unexpected(Error::Clock);
        }
        state.observed_ = value->time;
        return *value;
    }

    /// Lookup under domain lock; missing entries return null without directory allocation or Scope quota use.
    /// Raw borrows cannot outlive the caller's lock or State. Each entry point validates input.
    static Projection* locate(State& state, const Scope& scope) {
        const auto sector = state.scenes_.find(scope.sector);
        if (sector == state.scenes_.end()) {
            return nullptr;
        }
        const auto spectrum = sector->second.find(scope.spectrum); // Each Spectrum retains an independent cursor within its Sector.
        return spectrum == sector->second.end() ? nullptr : &spectrum->second;
    }

    /// Requires exclusive domain lock; invalid Scope or exhausted quota returns an error. Existing Scopes do not consume another slot.
    /// New projections inherit domain lock, content costing, and limits; construction failure removes a newly created empty Sector.
    /// Later preparation failure is handled by State::Pending, which removes the new Scope.
    static std::expected<Projection*, Error> obtain(State& state, const Scope& scope) {

        if (!scope.valid()) {
            return std::unexpected(Error::Input);
        }
        if (auto* scene = locate(state, scope)) {
            return scene;
        }
        if (state.scopes_ == state.limits_.scopes) {
            return std::unexpected(Error::Capacity);
        }

        auto [sector, created] = state.scenes_.try_emplace(scope.sector);
        try {
            auto [spectrum, inserted] = sector->second.try_emplace(scope.spectrum, state.gate_, static_cast<typename Projection::Measure>(&State::measure), state.limits_.projection);
            state.scopes_ += inserted; // Count only successfully constructed projections; failure consumes no quota.
            return &spectrum->second;
        } catch (...) {
            if (created) {
                state.scenes_.erase(sector);
            }
            throw;
        }
    }

    /// State and Scene are domain-protected; total usage includes Scene's old history, whose allowance can be reused.
    static std::size_t allowance(const State& state, const Projection& scene) {
        return state.limits_.history - (state.history_ - scene.history());
    }

    /// Requires exclusive domain lock after the Scene candidate commits; before is the pre-preparation history cost.
    /// Update domain accounting before invoking the bounded noexcept internal collector with a named event.
    /// Catalog batch envelopes lack a per-item name; their batch path explicitly supplies Scope for accounting and notification.
    static void publish(State& state, Projection& scene, std::size_t before, const typename Projection::Event& event) noexcept {
        state.history_ = state.history_ - before + scene.history();
        if (state.notify_) {
            state.notify_(state.context_, *event.name->scope, event);
        }
    }
};
} // namespace astra
