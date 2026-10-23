// Convert Windows' 100 ns interrupt counter without signed overflow.
#pragma once
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace astra::windows {
/// Return a nonnegative nanosecond coordinate, rejecting unrepresentable uptime.
[[nodiscard]] constexpr std::int64_t nanoseconds(std::uint64_t ticks) {

    if (ticks > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 100) {
        throw std::overflow_error("Elapsed clock coordinate exhausted");
    }
    return static_cast<std::int64_t>(ticks * 100);
}
} // namespace astra::windows
