// Schedule domain deadlines and intrusive hooks from explicitly advanced time.
#pragma once
#include "wheel.hpp"
#include <astra/clock.hpp>
#include <astra/profile.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <stdexcept>

namespace astra {
/// Deadline scheduler for one dynamic source group, created on its first finite lease. The domain commit guard serializes every operation.
/// Stores only a group time anchor; native records supply deadlines without per-record duplication.
class Agenda {
    /// Four levels of 256 slots at 10 ms ticks cover about 497 days. Later valid deadlines are rescheduled when reached.
    using Timer = Wheel<4, 8>;

public:
    /// Hook embedded in a stable native-record handle, without payload ownership; follows Wheel::Node move/copy constraints.
    using Node = Timer::Node;
    /// Fixed positive tick length; sub-tick remainder is retained for the next advance.
    static constexpr auto interval = std::chrono::milliseconds(10);

    /// Initial established nonnegative Unix nanoseconds, without replaying ticks since 1970; invalid time throws invalid_argument.
    explicit Agenda(Clock::Time initial) : time_(initial) {
        if (initial.time_since_epoch().count() < 0) {
            throw std::invalid_argument("Agenda requires nonnegative Unix time");
        }
    }

    /// Completed group tick boundary, not wall time; changes only after a complete tick.
    Clock::Time time() const noexcept {
        return time_ + (timer_.now() == tick_ ? std::chrono::milliseconds::zero() : interval);
    }

    /// Next full-tick boundary for skipping rounds that cannot advance; saturates without time overflow.
    Clock::Time next() const noexcept {
        const auto current = time();
        return Clock::Time::max() - current < interval ? Clock::Time::max() : current + interval;
    }

    /// Schedules finite deadlines from the current boundary; expired records run next tick without synchronous business callbacks.
    /// Allocation-free and noexcept. Advance to final acceptance time before committing the native deadline and hook.
    void set(Node& node, Clock::Time deadline) noexcept {

        const auto boundary = time(); // Wheel may already have advanced inside a callback; do not reschedule from the prior tick's anchor.
        const auto remaining = deadline > boundary ? deadline - boundary : std::chrono::nanoseconds::zero();
        const auto delay = static_cast<std::uint64_t>(remaining / interval + (remaining % interval != std::chrono::nanoseconds::zero())); // Round up using quotient and remainder without first expanding remaining.
        static_cast<void>(timer_.schedule(node, std::min(delay, Timer::limit)));
    }

    /// Unschedules without destroying the node; detached hooks are accepted.
    static void erase(Node& node) noexcept {
        Timer::cancel(node);
    }

    /// Advances complete ticks through now. fire(node, boundary) must recheck the actual deadline; an intermediate wakeup is not expiration.
    /// A successful fire may destroy the node. Before throwing, it must preserve the node and leave business state uncommitted; advance reschedules and rethrows.
    /// Earlier completed expirations are not rolled back. On failure, the caller must stop promising that affected views are caught up.
    template <typename F>
    void advance(Clock::Time now, F&& fire) {

        ASTRA_PROFILE_SCOPE("star.agenda.advance");

        if (now < time_) {
            throw std::invalid_argument("Agenda time cannot move backwards");
        }
        const auto pending = static_cast<std::uint64_t>((now - time_) / interval);
        for (std::uint64_t step = 0; step < pending; ++step) {
            try {
                timer_.tick([&](Node* node) {
                    const auto boundary = time(); // Distinguish a ready queue left by a prior exception from the new tick.
                    try {
                        fire(node, boundary);
                    } catch (...) {
                        static_cast<void>(timer_.schedule(*node, 1)); // Reschedule the uncommitted record without allocation for the next tick.
                        throw;
                    }
                });
            } catch (...) {
                time_ = time(); // If Wheel advanced, update the anchor even on failure to avoid replaying a tick.
                tick_ = timer_.now();
                throw;
            }
            time_ = time();
            tick_ = timer_.now();
        }
    }

private:
    /// Actual completed tick boundary, synchronized with timer_; no per-record remaining TTL.
    Clock::Time time_;
    /// Wheel position matching time_, detecting callback-time advancement.
    std::uint64_t tick_{};
    /// Stable group wheel; Wheel detaches hooks regardless of node/wheel destruction order.
    Timer timer_;
};
} // namespace astra
