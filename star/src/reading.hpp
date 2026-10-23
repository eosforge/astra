// Share read locking and wait boundaries without taking over domain expiry or source policy.
#pragma once
#include <astra/profile.hpp>

#include <expected>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <type_traits>
#include <utility>
#include <vector>

namespace astra {
/// Shared dynamic-domain read synchronization. Each State retains its clock, expiration rules, and source-lock type.
/// Shares lock/wait/reclamation order only, without unified storage, new runtime objects, or virtual calls.
template <typename State>
class Reading {
public:
    /// Runs synchronous action once, returning expected<T, State::Error>. No State reentry or protected raw borrows in results.
    /// Release domain before destroying old records on error/exception. Release it while waiting for source preparation, then resample time.
    static auto execute(State& state, auto&& action) {

        ASTRA_PROFILE_SCOPE("star.reading.execute");

        using Result = std::invoke_result_t<decltype(action)>; // Preserves domain-specific errors, including clock failure.
        {
            ASTRA_PROFILE_BEGIN(profileLock20, "star.reading.execute.wait.lock");
            const std::shared_lock lock(*state.gate_); // Reads within the current full tick avoid source preparation locks.
            ASTRA_PROFILE_END(profileLock20);
            const auto stamp = state.reading(); // Retain State's local-time and monotonic checks.
            if (!stamp) {
                return Result(std::unexpected(stamp.error()));
            }
            if (stamp->time < state.due_) {
                return std::forward<decltype(action)>(action)();
            }
        }

        ASTRA_PROFILE_COUNT("star.reading.expiry_fallback", 1);
        std::vector<typename State::Retired> retired; // Declare before domain lock so exceptional reclamation also runs outside it.
        ASTRA_PROFILE_BEGIN(profileLock29, "star.reading.execute.wait.lock");
        std::unique_lock lock(*state.gate_); // Reacquiring exclusive access invalidates the earlier time reading.
        ASTRA_PROFILE_END(profileLock29);
        for (;;) {
            const auto stamp = state.reading(); // Resample after each source wait; old readings cannot prove catch-up.
            if (!stamp) {
                return Result(std::unexpected(stamp.error()));
            }
            auto blocked = state.advance(stamp->time, retired); // Domain-specific expiration returns a busy source or null.
            if (!blocked) {
                return std::forward<decltype(action)>(action)();
            }
            typename State::Guard waiting(std::move(blocked), lock); // Guard releases domain while waiting, then reacquires it and retries.
        }
    }
};
} // namespace astra
