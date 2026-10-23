// Separate suspend-inclusive local samples from calibrated, nondecreasing business epoch time.
#pragma once
#include <astra/types.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <optional>
#include <stop_token>

namespace astra {
/// Initial calibration and synchronization-quality limit shared by Pulsar and Star, in ns; calibrated Star leases are not gated by it.
inline constexpr std::uint64_t clockUncertaintyLimitNanoseconds = 500'000'000;

/// Provide nondecreasing Unix nanoseconds for business state without allocation, disk writes, or RPC during reads.
class Clock {
public:
    /// Tag the business chrono coordinate without now(), preventing uncalibrated wall time from entering business data.
    struct Origin;
    /// Fixed nanosecond Unix coordinate used by calibrated business records and deadlines.
    using Time = std::chrono::time_point<Origin, std::chrono::nanoseconds>;

    /// Suspend-inclusive platform time for local sampling, never a business deadline.
    struct Elapsed {
        /// Express local elapsed counts in fixed nanoseconds.
        using duration = std::chrono::nanoseconds;
        /// Preserve chrono's signed nanosecond representation.
        using rep = duration::rep;
        /// One count represents one nanosecond.
        using period = duration::period;
        /// Local coordinate with no Unix epoch interpretation.
        using time_point = std::chrono::time_point<Elapsed>;
        /// Native adapters promise no backward steps in this local coordinate.
        static constexpr bool is_steady = true;
        /// Throw on native clock failure or counter overflow instead of returning a false zero-time success.
        static time_point now();
    };

    /// Local sample coordinate accepted by deterministic state-machine entry points.
    using ElapsedTime = Elapsed::time_point;

    /// Target time from a valid observation; publication does not directly replace the exposed business clock.
    struct Estimate {
        /// Nonnegative Unix nanoseconds estimated at sampled.
        Time time{};
        /// Same-process suspend-inclusive receive time for sample ordering and age calculations.
        ElapsedTime sampled{};
        /// Upstream, network, and quantization error, excluding local correction not yet absorbed.
        std::uint64_t uncertaintyNanoseconds{};
        /// Selected sample's round-trip delay; zero for a local physical-reference observation.
        std::uint64_t rttNanoseconds{};
    };

    /// Classify finite-deadline construction failures independently of network Status.
    enum class Error {
        /// No usable local reading for a new finite deadline; reference loss alone does not imply this error.
        ClockUnready,
        /// Negative TTL or an invalid caller-supplied time reading.
        InvalidTime,
        /// Addition would exceed the fixed nanosecond coordinate's representable range.
        Exhausted
    };

    /// One coherent clock observation with separate local-readiness and reference-quality flags.
    struct Reading {
        /// Continuous nondecreasing Unix time that keeps advancing after reference loss.
        Time time{};
        /// Sum of upstream error, age drift, and unabsorbed correction; not a hard real-time guarantee.
        std::uint64_t uncertaintyNanoseconds{};
        /// Latest sample's round-trip duration, for diagnostics only.
        std::uint64_t rttNanoseconds{};
        /// Last valid observation time, distinguishing fresh samples after reconnection.
        ElapsedTime sampled{};
        /// True only with an epoch anchor and valid local advancement; false by default so empty readings cannot issue deadlines.
        bool ready{};
        /// True for trusted samples at most 5 s old with at most 500 ms total error; false by default, never a renewal gate.
        bool synchronized{};
        /// Return one absolute deadline only when ready, ttl is nonnegative, and addition fits; never map failure to Store's unlimited lifetime.
        std::expected<Time, Error> deadlineAfter(std::chrono::nanoseconds ttl) const noexcept;
    };

    /// Accept 1..1000 ppm maximum extra slew; Star defaults to 1000 ppm to track Pulsar's 500 ppm adjustment with margin.
    explicit Clock(std::uint32_t slewPpm = 1000);
    /// Return no reading before initialization or after latched local failure; native clock errors throw. Reference loss retains the anchor.
    std::optional<Clock::Reading> now() const;
    /// Read at an injected local time for deterministic driving; out-of-order input latches a timing-facility failure.
    std::optional<Clock::Reading> now(ElapsedTime local) const;
    /// Validate and extrapolate to consumption time before replacing residual correction; invalid, stale, or duplicate samples preserve the model.
    bool publish(const Clock::Estimate& estimate);
    /// Apply the same publication rules at an explicitly supplied local time for deterministic driving.
    bool publish(const Clock::Estimate& estimate, ElapsedTime local);
    /// Revoke reference quality while retaining local time and finite deadlines; a subsequent valid sample can restore synchronization.
    void revoke();

private:
    /// Advance under mutex_; arithmetic exhaustion or backward local time remains latched until process restart.
    bool advance(ElapsedTime local) const;
    /// Read the advanced model under mutex_, retaining any latched timing-facility failure.
    std::optional<Clock::Reading> read(ElapsedTime local) const;
    /// Validate and absorb one estimate under mutex_ without bypassing local-clock failure checks.
    bool observe(const Clock::Estimate& estimate, ElapsedTime local);
    /// Protect model state; default entry points sample only after locking to avoid false reordering between callers.
    mutable std::mutex mutex_;
    /// Maximum extra slew, not the underlying oscillator's accuracy.
    const std::uint32_t slewPpm_;
    /// Empty until the first public epoch anchor has been established.
    std::optional<Clock::Estimate> estimate_;
    /// Local elapsed-time anchor paired with epoch_.
    mutable ElapsedTime local_{};
    /// Published time, never replaced by a jump during observation.
    mutable Time epoch_{};
    /// Unabsorbed signed correction: positive speeds up time, negative slows it down.
    mutable std::int64_t debt_{};
    /// Remainder from ppm division, preserving small-step correction without accumulating unused credit.
    mutable std::uint64_t fraction_{};
    /// Reference qualification is independent of whether an epoch anchor exists.
    bool trusted_{};
    /// Backward or exhausted local counters cannot be repaired by a network sample.
    mutable bool failed_{};
};

/// Shared local sample coordinate for clock clients and native adapters.
using ElapsedTime = Clock::ElapsedTime;

/// Return the local sample coordinate as a fixed nanosecond count.
std::int64_t elapsedNanoseconds(ElapsedTime local) noexcept;
/// Measure suspend-inclusive native clock precision and read cost with a 200 ms budget and cooperative stop.
/// Failures throw; run only on the dedicated sampling thread, never the Runtime control loop.
std::uint64_t elapsedPrecisionNanoseconds(std::stop_token stop = {});
} // namespace astra
