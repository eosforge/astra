// Coordinate private recovery preparation before replacing visible source state.
#pragma once
#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace astra {
/// Private dynamic-source recovery, at most one Scope per step. Destruction cancels remaining work without rolling back published Scopes.
template <typename State>
class Restore {
public:
    /// Domain capacity/conflict errors, without another network error code set.
    using Error = typename State::Error;

    /// Unique full candidate; cannot copy and advance one task twice.
    Restore(Restore&&) noexcept = default;
    /// Keep one owner of recovery task and its advancement; copying is forbidden.
    Restore(const Restore&) = delete;
    /// Keep one owner of recovery task and its advancement; copying is forbidden.
    Restore& operator=(const Restore&) = delete;
    /// State retains Scope coverage; abandoning the task cannot let late increments overwrite installed content.
    ~Restore() = default;

    /// True means every Scope and source confirmation completed; false means more work. After failure, returns the same error without continuing.
    std::expected<bool, Error> step() {

        ASTRA_PROFILE_SCOPE("star.restore.step");

        if (failure_) {
            return std::unexpected(*failure_);
        }
        if (done_) {
            return true;
        }
        if (offset_ < scopes_.size()) {
            const auto& scope = scopes_[offset_]; // Fixed Scope addresses; no commit lock survives step return.
            const auto result = owner_->install(id_, draft_, scope);
            if (!result) {
                if (result.error() != Error::Capacity || retried_) {
                    failure_ = result.error();
                    return std::unexpected(*failure_);
                }
                deferred_.push_back(std::move(scopes_[offset_])); // Let other Scopes release capacity, then retry at most once; never busy-wait on a hot Scope.
            }
            ++offset_;
            return false;
        }

        if (!deferred_.empty()) {
            scopes_.swap(deferred_);
            deferred_.clear();
            offset_ = 0;
            retried_ = true;
            return false;
        }
        const auto result = owner_->finish(id_, draft_.position()); // The only source-wide completion confirmation point.
        if (!result) {
            failure_ = result.error();
            return std::unexpected(*failure_);
        }
        done_ = true;
        return true;
    }

private:
    friend State;

    /// State already validated candidate, identity, and capacity. Scopes are the ordered union of old/new source Scopes.
    Restore(State& owner, std::string id, typename State::Source::Draft draft, std::vector<Scope> scopes) : owner_(&owner), id_(std::move(id)), draft_(std::move(draft)), scopes_(std::move(scopes)) {
        deferred_.reserve(scopes_.size()); // Preallocate retry bookkeeping before installation.
    }

    /// State outlives task, matching Exchange's existing borrow boundary.
    State* owner_;
    /// Owned fixed source identity, without temporary strings across control rounds.
    std::string id_;
    /// Unique complete candidate; all network pages validated before task creation.
    typename State::Source::Draft draft_;
    /// Per-step Scope inventory, without copied bodies.
    std::vector<Scope> scopes_;
    /// Capacity-rejected Scopes, retried once after other Scopes finish.
    std::vector<Scope> deferred_;
    /// Next Scope index, initially zero.
    std::size_t offset_{};
    /// First terminal error; repeated step never retries failed tasks.
    std::optional<Error> failure_;
    /// Whether the sole capacity-retry pass has started.
    bool retried_{};
    /// Full-source confirmation published; repeated step returns true idempotently.
    bool done_{};
};
} // namespace astra
