// Select bounded four-timestamp clock estimates and retain sample-quality information.
#pragma once
#include <astra/clock.hpp>

#include <cstdint>
#include <optional>

namespace astra {
/// Single-RPC NTP four-timestamp batch filter selects the valid observation with minimum round-trip delay.
class Filter {
public:
    /// localPrecision is local BOOTTIME rho, in 1 ns..20 ms.
    explicit Filter(std::uint64_t localPrecision = 1);
    /// t0/t3 use local BOOTTIME; t1/t2 use Unix time. One batch belongs to one RPC.
    /// Reject unsynchronized sources, reversed or out-of-range timestamps, and RTT above 200 ms; tolerate negative delay within quantization/rate budgets.
    bool observe(std::uint64_t t0, std::uint64_t t1, std::uint64_t t2, ElapsedTime t3, std::uint64_t precision, std::uint64_t uncertainty, bool synchronized);
    /// Requires at least three valid samples before returning minimum delay, retaining all precision allowances.
    std::optional<Clock::Estimate> result() const;

private:
    /// Validated at construction; network input cannot expand it.
    std::uint64_t localPrecision_;
    /// Fixed-size minimum-delay observation without allocation.
    std::optional<Clock::Estimate> best_;
    /// Valid-sample count, saturating at eight.
    unsigned count_{};
};
} // namespace astra
