// Coordinate cancellation and completion before releasing asynchronous SDK resources.
#include "lifetime.hpp"

#include <stdexcept>
#ifdef _WIN32
#include <windows.h>

// realtimeapiset needs Windows base types and architecture macros; include it after windows.h.
#include <realtimeapiset.h>
#else
#include <ctime>
#endif

namespace comet::detail {
/// Lifetime::now reads suspend-inclusive monotonic milliseconds, independent of wall-clock adjustments.
/// Does not throw; overflow or clock failure returns no time.
std::optional<Lifetime::Time> Lifetime::now() noexcept {
#ifdef _WIN32
    // Windows 10/Server 2016 provides precise interrupt time in 100 ns units, including suspend compensation.
    // Dividing by 10000 fits nonnegative int64 and floors to milliseconds like Linux.
    ULONGLONG value{};
    ::QueryInterruptTimePrecise(&value);
    return static_cast<Time>(value / 10'000);
#else
    timespec value{}; // Kernel-provided seconds and nanoseconds must fit nonnegative int64 milliseconds.
    if (::clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1'000'000'000 || static_cast<std::uint64_t>(value.tv_sec) > static_cast<std::uint64_t>((std::numeric_limits<Time>::max() - 999) / 1000)) {
        return std::nullopt;
    }
    return static_cast<Time>(value.tv_sec) * 1000 + value.tv_nsec / 1'000'000;
#endif
}

Lifetime::Lifetime(std::chrono::milliseconds ttl) : ttl_(ttl >= std::chrono::seconds(1) && ttl <= std::chrono::minutes(10) ? ttl.count() : throw std::invalid_argument("Invalid lease TTL")), period_(ttl_ / 3) {
}

bool Lifetime::confirm(Time sent) noexcept {
    if (sent < 0 || sent > std::numeric_limits<Time>::max() - ttl_) {
        return false;
    }
    if (!sent_ || sent > *sent_) {
        sent_ = sent;
    }
    return true;
}
} // namespace comet::detail
