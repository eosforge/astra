// Measure native elapsed-clock granularity within an explicit cancellation and duration budget.
#pragma once
#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace astra {
/// read returns nonnegative monotonic nanoseconds; running uses an independent budget/cancellation source, not read values or call counts.
/// minimum is max(reported resolution, representation unit), in 1 ns..20 ms. Insufficient or reversed samples throw explicitly.
inline std::uint64_t measureClockPrecision(auto read, auto running, std::uint64_t minimum) {

    if (minimum == 0 || minimum > 20'000'000) {
        throw std::invalid_argument("Invalid minimum clock precision");
    }

    // before retains the latest reading; equal readings are not samples, so wait for actual tick edges.
    std::int64_t before = read();
    if (before < 0) {
        throw std::runtime_error("Negative monotonic clock reading");
    }

    // best is the minimum positive increment; edges counts clock changes rather than repeated equal reads.
    auto best = std::numeric_limits<std::uint64_t>::max();
    // Require at least three actual edges and stop searching at 32.
    unsigned edges = 0;
    // Target 32 edges; every 128 reads check the independent budget. This batch size limits checking overhead, not total samples or clock validity.
    while (edges < 32 && running()) {
        // sample bounds reads within this batch; running checks time and cancellation between batches.
        for (unsigned sample = 0; sample < 128 && edges < 32; ++sample) {
            // after is the current reading; only an ordered difference from before is a resolution candidate.
            const std::int64_t after = read();
            if (after < before) {
                throw std::runtime_error("Monotonic clock moved backwards");
            }
            if (after > before) {
                best = std::min(best, static_cast<std::uint64_t>(after - before));
                ++edges;
            }
            before = after;
        }
    }

    // Coarse clocks may yield fewer than 32 edges within budget, but require three; never fall back to reported precision without samples.
    if (edges < 3 || best > 20'000'000) {
        throw std::runtime_error("Cannot measure supported monotonic clock precision");
    }
    return std::max(minimum, best);
}
} // namespace astra
