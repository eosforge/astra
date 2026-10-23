// Provide native source-export fixtures for controlled replication and recovery checks.
#pragma once
#include "check.hpp"

#include <atomic>
#include <chrono>
#include <expected>
#include <future>
#include <optional>
#include <semaphore>
#include <thread>

namespace {
/// Shared lock-boundary check for both real domains; write creates one native record without fake source/projection state.
template <typename State>
void exports(auto&& write) {

    using namespace std::chrono_literals;
    using astra::Clock;
    const astra::Scope scope{"export", "boundary"};
    std::atomic_bool pause{}, available{true};     // Pause one time sample; available models temporary clock unavailability.
    std::atomic_uint samples{};                    // Export must neither sample time nor trigger GC.
    std::binary_semaphore entered{0}, released{0}; // Coordinates held domain lock and permission to finish sampling.
    State state([&]() -> std::optional<Clock::Reading> {
        ++samples;
        if (pause.exchange(false)) {
            entered.release();
            static_cast<void>(released.try_acquire_for(3s)); // Bound exception cleanup so the fixture worker cannot retain the lock forever.
        }
        return available ? std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}) : std::nullopt;
    },
                {});
    const auto key = write(state, scope);
    CHECK(!key.empty());
    const auto position = state.source().position();
    CHECK(position == 1);

    // Pause time sampling under exclusive maintenance, exposing exports that incorrectly share the domain lock.
    pause = true;
    auto maintenance = std::async(std::launch::async, [&] { state.tick(); }); // An existing finite lease forces tick to sample rather than take the empty-domain early exit.
    entered.acquire();
    auto exported = std::async(std::launch::async, [&] {
        const auto view = state.source();
        const auto events = state.events(0);
        const auto delivery = state.deliver(0, 8, 4096);
        const auto point = state.resolve(scope, key);
        return view.position() == position && events && events->size() == 1 && delivery && point && point->record;
    });
    const bool independent = exported.wait_for(1s) == std::future_status::ready; // Bound detection and unblock before asserting even on failure.
    released.release();
    maintenance.get(); // Unblock and join maintenance, propagating exceptions on the fixture thread.
    CHECK(exported.get() && independent);

    // Original absolute deadlines let export work without current time; public views still report clock errors.
    available = false;
    const auto before = samples.load();
    CHECK(state.source().position() == position && state.events(0) && state.deliver(0, 8, 4096));
    CHECK(state.resolve(scope, key)->record && samples.load() == before);
    CHECK(state.capture(scope) == std::unexpected(State::Error::Clock));
}
} // namespace
