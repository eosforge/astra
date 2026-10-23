// Pure Member-replacement and bounded reconnect-backoff rules.
#include <astra/policy.hpp>

#include <algorithm>

namespace astra {
/// Returns true for a valid newer candidate, false for equal unchanged identity, or Status for conflicts/regression.
Result<bool> supersedes(const Member& candidate, const Member& current) {

    // Deployment binding is immutable and equal epochs require identical values; only a newer epoch replaces identity.

    if (candidate.principal != current.principal || candidate.role != current.role || candidate.address != current.address || candidate.galaxy != current.galaxy || candidate.epoch < current.epoch || (candidate.epoch == current.epoch && candidate != current)) {
        return Status::conflict("Conflicting or stale member incarnation");
    }

    return candidate.epoch > current.epoch;
}

/// Computes jittered retry delay from consecutive failures, configured bounds, and desynchronization salt.
Milliseconds retryDelay(std::uint32_t failures, const Config& config, std::uint64_t salt) {

    // Cap exponent before arithmetic and clamp jitter to configured bounds, retaining variation at sustained-failure limits.
    // Exponent capped at 16 to prevent overflow.
    const auto shift = std::min(failures == 0 ? 0 : failures - 1, 16U);
    // Base delay is reconnectMin * 2^shift, capped at reconnectMax.
    const auto base = std::min(config.reconnectMin * (1U << shift), config.reconnectMax);
    // Jitter lower bound is base minus one quarter, clamped to reconnectMin.
    const auto lower = std::max(base - base / 4, config.reconnectMin);
    // Jitter upper bound is base plus one quarter, clamped to reconnectMax.
    const auto upper = std::min(base + base / 4, config.reconnectMax);

    return lower + Milliseconds((salt + failures) % static_cast<std::uint64_t>((upper - lower).count() + 1));
}
} // namespace astra
