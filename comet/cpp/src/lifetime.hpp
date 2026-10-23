// Coordinate cancellation and completion before releasing asynchronous SDK resources.
#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace comet::detail {
/// Local lease-confirmation budget retains only the latest successful start, without server epochs or renewal history.
class Lifetime {
public:
    /// Nonnegative suspend-inclusive monotonic milliseconds since boot, not wall time.
    using Time = std::int64_t;
    /// Clock failure returns empty, without fabricating time or falling back to wall time.
    static std::optional<Time> now() noexcept;

    /// Accept TTLs from one second through ten minutes; reject invalid configuration with invalid_argument.
    explicit Lifetime(std::chrono::milliseconds ttl);

    /// Set fixed per-UUID renewal-period jitter of about +/-10%; this seed is not a random identity.
    void spread(std::size_t seed) noexcept {
        period_ = ttl_ / 3 - ttl_ / 30 + static_cast<Time>(seed % static_cast<std::size_t>(2 * (ttl_ / 30) + 1));
    }

    /// Confirmation uses the first send time; retries and response arrival never restore a full TTL.
    bool confirm(Time sent) noexcept;

    /// Check the confirmed lease at now; missing time or negative clock anomalies cannot establish readiness.
    bool ready(std::optional<Time> now) const noexcept {
        return now && sent_ && *now >= *sent_ && *now - *sent_ < ttl_;
    }

    /// Schedule one current attempt after a missed period without replaying each missed beat.
    bool due(Time now) const noexcept {
        return !sent_ || now < *sent_ || now - *sent_ >= period_;
    }

    /// Return the next wake delay; this does not establish successful renewal.
    std::chrono::milliseconds delay(Time now) const noexcept {
        return due(now) ? std::chrono::milliseconds::zero() : std::chrono::milliseconds(period_ - (now - *sent_));
    }

    /// Discard confirmation when changing UUID; old budgets cannot cross identities.
    void reset() noexcept {
        sent_.reset();
    }

private:
    /// Fixed request TTL in milliseconds.
    const Time ttl_;
    /// About TTL/3; even a one-second lease schedules in hundreds of milliseconds.
    Time period_;
    /// First-send start of the latest complete success; initially unconfirmed.
    std::optional<Time> sent_;
};
} // namespace comet::detail
