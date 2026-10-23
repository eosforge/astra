// Filter clock observations and advance calibrated epoch time without backward publication.
#include "clock_filter.hpp"
#include <astra/profile.hpp>

#include <algorithm>
#include <limits>
#include <numeric>
#include <stdexcept>

namespace astra {
namespace {
/// Divide before multiplying to avoid age * ppm overflow; round up so one-nanosecond uncertainty is not underestimated.
std::uint64_t drift(std::uint64_t age, std::uint32_t ppm) noexcept {
    return age / 1'000'000 * ppm + (age % 1'000'000 * ppm + 999'999) / 1'000'000;
}

/// Residuals subtract two nonnegative int64 coordinates and therefore cannot equal INT64_MIN.
std::uint64_t magnitude(std::int64_t value) noexcept {
    return static_cast<std::uint64_t>(value < 0 ? -value : value);
}

/// Signed upper bound of Unix and elapsed nanosecond coordinates; check every addition before committing.
constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
/// Accept samples and report synchronization quality within 5 s, including suspend; initialized clocks retain finite-lease capability afterward.
constexpr std::uint64_t freshness = 5'000'000'000;
} // namespace

std::int64_t elapsedNanoseconds(ElapsedTime local) noexcept {
    return local.time_since_epoch().count();
}

Filter::Filter(std::uint64_t localPrecision) : localPrecision_(localPrecision) {

    if (localPrecision == 0 || localPrecision > 20'000'000) {
        throw std::invalid_argument("Invalid local clock precision");
    }
}

/// Filter one four-timestamp sample, preserving prior selection when input is rejected.
/// t0/t1/t2 describe send and server receive/send times; received is the local receive coordinate.
/// precision and uncertainty describe the peer; synchronized reports its reference qualification.
/// Return whether the sample was accepted, without changing selected results on rejection.
bool Filter::observe(std::uint64_t t0, std::uint64_t t1, std::uint64_t t2, ElapsedTime received, std::uint64_t precision, std::uint64_t uncertainty, bool synchronized) {

    ASTRA_PROFILE_SCOPE("common.clock.Filter.observe");

    // t3 shares t0's local elapsed coordinate; reject negatives before converting to unsigned.
    const auto t3 = elapsedNanoseconds(received);
    ASTRA_PROFILE_COUNT("clock.filter.t0_elapsed_ns", t0);
    ASTRA_PROFILE_COUNT("clock.filter.t1_unix_ns", t1);
    ASTRA_PROFILE_COUNT("clock.filter.t2_unix_ns", t2);
    ASTRA_PROFILE_VALUE("clock.filter.t3_elapsed_ns", t3);
    ASTRA_PROFILE_COUNT("clock.filter.upstream_ns", uncertainty);
    ASTRA_PROFILE_COUNT("clock.filter.remote_precision_ns", precision);
    ASTRA_PROFILE_COUNT("clock.filter.local_precision_ns", localPrecision_);
    // Bound remote unsigned coordinates so signed differences and midpoint arithmetic remain representable.
    const auto limit = static_cast<std::uint64_t>(maximum);
    if (!synchronized || precision == 0 || precision > 20'000'000 || uncertainty > clockUncertaintyLimitNanoseconds || t0 > limit || t1 > limit || t2 > limit || t3 < 0 || t0 > static_cast<std::uint64_t>(t3) || t2 < t1) {
        ASTRA_PROFILE_COUNT("clock.filter.rejected", 1); // Reject invalid coordinates or quality before unchecked unsigned subtraction.
        return false;
    }

    // Local round-trip duration in ns; earlier validation established t3 >= t0.
    const auto elapsed = static_cast<std::uint64_t>(t3) - t0;
    // Server processing duration in ns, never directly compared to the local clock's origin.
    const auto processing = t2 - t1;
    ASTRA_PROFILE_COUNT("clock.filter.elapsed_ns", elapsed);
    ASTRA_PROFILE_COUNT("clock.filter.processing_ns", processing);
    if (elapsed > 200'000'000 || processing > 200'000'000) {
        ASTRA_PROFILE_COUNT("clock.filter.rejected", 2); // Round-trip or server processing duration exceeds its bound.
        return false;
    }

    // Allow 500 ppm per oscillator plus Pulsar's 500 ppm slew; upstream absolute uncertainty cannot relax processing-duration checks.
    const auto dispersion = localPrecision_ + precision + drift(elapsed, 1500);
    if (processing > elapsed && processing - elapsed > 2 * dispersion) {
        ASTRA_PROFILE_COUNT("clock.filter.rejected", 3); // Endpoint processing durations exceed tolerated quantization error.
        return false;
    }

    // Estimate Unix-to-local offset from four timestamps; midpoint avoids overflowing the sum of two differences.
    const auto offset = std::midpoint(static_cast<std::int64_t>(t1) - static_cast<std::int64_t>(t0), static_cast<std::int64_t>(t2) - t3);
    if ((offset > 0 && t3 > maximum - offset) || (offset < 0 && offset < -t3)) {
        ASTRA_PROFILE_COUNT("clock.filter.rejected", 4); // Mapping would leave the representable Unix-time range.
        return false;
    }

    // Network round-trip duration excludes processing, floors quantization negatives at zero, and is at least local resolution.
    const auto rtt = std::max(elapsed > processing ? elapsed - processing : 0, localPrecision_);
    // Combine upstream, quantization, drift, and half-round-trip error; round up and retain 1 ns for midpoint rounding.
    const auto error = uncertainty + dispersion + (rtt + 1) / 2 + 1;
    ASTRA_PROFILE_COUNT("clock.filter.rtt_ns", rtt);
    ASTRA_PROFILE_COUNT("clock.filter.uncertainty_ns", error);
    ASTRA_PROFILE_COUNT("clock.filter.rejected", 0);
    if (!best_ || rtt <= best_->rttNanoseconds) {
        best_ = Clock::Estimate{Clock::Time(std::chrono::nanoseconds(t3 + offset)), received, error, rtt};
    }
    count_ = std::min(count_ + 1, 8U);
    return true;
}

/// Read the best estimate from this filter batch, or no estimate if no sample was accepted.
/// Selection state remains unchanged.
std::optional<Clock::Estimate> Filter::result() const {
    return count_ >= 3 ? best_ : std::nullopt;
}

/// Construct a finite deadline from this reading, rejecting unready state, invalid time, and overflow.
/// ttl is the requested lifetime; the reading itself remains unchanged.
std::expected<Clock::Time, Clock::Error> Clock::Reading::deadlineAfter(std::chrono::nanoseconds ttl) const noexcept {

    // The reading's Unix nanosecond coordinate and the requested duration must both be nonnegative.
    // ready denotes local time availability; stale synchronization does not prevent calibrated Stars from creating or extending finite leases.
    const auto base = time.time_since_epoch().count();
    if (!ready) {
        return std::unexpected(Clock::Error::ClockUnready);
    }
    if (base < 0 || ttl.count() < 0) {
        return std::unexpected(Clock::Error::InvalidTime);
    }
    if (ttl.count() > maximum - base) {
        return std::unexpected(Clock::Error::Exhausted);
    }
    return time + ttl;
}

/// Store the maximum extra slew without starting sampling or initializing an epoch anchor.
/// slewPpm is the additional adjustment limit in parts per million.
Clock::Clock(std::uint32_t slewPpm) : slewPpm_(slewPpm) {

    if (slewPpm == 0 || slewPpm > 1000) {
        throw std::invalid_argument("Epoch clock slew must be 1..1000 ppm");
    }
}

/// Advance elapsed time and absorb correction while holding the model mutex.
/// Return false and latch failure on backward local time or coordinate exhaustion.
bool Clock::advance(ElapsedTime local) const {

    if (failed_ || local < local_) {
        failed_ = true;
        return false;
    }

    // Ordered nonnegative anchors have a representable difference; retained fractions make small and large steps equivalent within one correction segment.
    const auto elapsed = static_cast<std::uint64_t>((local - local_).count());
    // Retain fractional ppm credit that has not yet accumulated a full nanosecond of correction.
    const auto fraction = elapsed % 1'000'000 * slewPpm_ + fraction_;
    // Divide before multiplying to bound the correction budget in ns over long elapsed intervals.
    const auto budget = elapsed / 1'000'000 * slewPpm_ + fraction / 1'000'000;
    // Cap correction at the residual so crossing the target cannot create artificial oscillation.
    const auto correction = std::min(magnitude(debt_), budget);
    // Add bounded slew; slewPpm_ <= 1000 prevents a negative correction from moving time backward.
    const auto step = debt_ < 0 ? elapsed - correction : elapsed + correction;
    // Check the last published Unix coordinate before changing anchors or residual correction.
    const auto base = epoch_.time_since_epoch().count();
    if (step > static_cast<std::uint64_t>(maximum - base)) {
        failed_ = true;
        return false;
    }
    epoch_ += std::chrono::nanoseconds(static_cast<std::int64_t>(step));
    debt_ += debt_ < 0 ? static_cast<std::int64_t>(correction) : -static_cast<std::int64_t>(correction);
    fraction_ = debt_ == 0 ? 0 : fraction % 1'000'000;
    local_ = local;
    return true;
}

/// Read at a supplied local coordinate under the model mutex without jumping published time.
/// Return no reading when initialization or local time advancement is unavailable.
std::optional<Clock::Reading> Clock::read(ElapsedTime local) const {

    if (!estimate_ || !advance(local)) {
        return std::nullopt;
    }

    // Sample age is nonnegative nanoseconds; the advanced local anchor cannot precede the observation.
    const auto age = static_cast<std::uint64_t>((local - estimate_->sampled).count());
    // Include oscillator and upstream-slew margin, plus local residual; a new sample cannot hide incomplete correction.
    const auto uncertainty = estimate_->uncertaintyNanoseconds + drift(age, 2000) + magnitude(debt_);
    return Clock::Reading{epoch_, uncertainty, estimate_->rttNanoseconds, estimate_->sampled, true, trusted_ && age <= freshness && uncertainty <= clockUncertaintyLimitNanoseconds};
}

/// Sample local time only after locking, preventing false ordering failures between concurrent readers.
/// Return no reading while the local clock is unready.
std::optional<Clock::Reading> Clock::now() const {

    ASTRA_PROFILE_SCOPE("common.clock.Clock.now");
    // Serialize anchor, residual, and qualification state; default entry points sample only after acquiring this lock.
    ASTRA_PROFILE_BEGIN(profileLock234, "common.clock.Clock.now.wait.lock");
    std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock234);
    return read(Clock::Elapsed::now());
}

/// Read at a caller-supplied coordinate so deterministic tests can inject backward time.
/// Return no reading when initialization or local time advancement is unavailable.
std::optional<Clock::Reading> Clock::now(ElapsedTime local) const {

    ASTRA_PROFILE_SCOPE("common.clock.Clock.now");
    // Serialize anchor, residual, and qualification state; default entry points sample only after acquiring this lock.
    ASTRA_PROFILE_BEGIN(profileLock242, "common.clock.Clock.now.wait.lock");
    std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock242);
    return read(local);
}

/// Absorb an external estimate under the mutex; invalid, stale, or duplicate observations preserve the model.
/// estimate and local identify the target and consumption coordinates; return whether the estimate was accepted.
bool Clock::observe(const Clock::Estimate& estimate, ElapsedTime local) {

    ASTRA_PROFILE_SCOPE("common.clock.Clock.observe");

    // Only initial calibration installs the target's nonnegative Unix coordinate directly as the published anchor.
    const auto target = estimate.time.time_since_epoch().count();
    ASTRA_PROFILE_VALUE("clock.model.target_unix_ns", target);
    ASTRA_PROFILE_VALUE("clock.model.local_elapsed_ns", elapsedNanoseconds(local));
    ASTRA_PROFILE_COUNT("clock.model.input_uncertainty_ns", estimate.uncertaintyNanoseconds);
    ASTRA_PROFILE_COUNT("clock.model.rtt_ns", estimate.rttNanoseconds);
    ASTRA_PROFILE_COUNT("clock.model.initialized", estimate_.has_value());
    if (failed_ || target < 0 || elapsedNanoseconds(estimate.sampled) < 0 || local < estimate.sampled || estimate.uncertaintyNanoseconds > 1'000'000'000 || estimate.rttNanoseconds > 200'000'000 || (estimate_ && estimate.sampled <= estimate_->sampled)) {
        ASTRA_PROFILE_COUNT("clock.model.rejected", 1); // Invalid, reordered, or duplicate input cannot change the continuous-time model.
        return false;
    }

    // Bound sample-to-consumption age by freshness before extrapolating the Unix coordinate.
    const auto age = (local - estimate.sampled).count();
    ASTRA_PROFILE_VALUE("clock.model.age_ns", age);
    if (static_cast<std::uint64_t>(age) > freshness || target > maximum - age) {
        ASTRA_PROFILE_COUNT("clock.model.rejected", 2); // Consumption delay exceeds the bound or extrapolation would overflow.
        return false;
    }

    // Extrapolate to consumption time; an initialized clock approaches this target gradually through debt_.
    const auto predicted = estimate.time + std::chrono::nanoseconds(age);
    if (!estimate_) {
        // Require sufficient initial quality instead of starting far from the correct epoch and spending hours slewing back.
        if (estimate.uncertaintyNanoseconds + drift(static_cast<std::uint64_t>(age), 2000) > clockUncertaintyLimitNanoseconds) {
            ASTRA_PROFILE_COUNT("clock.model.rejected", 3); // Initial calibration lacks quality; this differs from holdover on a running node.
            return false;
        }
        epoch_ = predicted;
        local_ = local;
    } else {
        if (!advance(local)) {
            ASTRA_PROFILE_COUNT("clock.model.rejected", 4); // A new sample cannot conceal failed or backward local advancement.
            return false;
        }

        // debt is the signed nanosecond difference from published time; changing correction direction discards the previous fractional budget.
        const auto debt = (predicted - epoch_).count();
        if ((debt < 0) != (debt_ < 0) || debt == 0) {
            fraction_ = 0;
        }
        debt_ = debt;
    }
    estimate_ = estimate;
    trusted_ = true;
    ASTRA_PROFILE_VALUE("clock.model.epoch_unix_ns", epoch_.time_since_epoch().count());
    ASTRA_PROFILE_VALUE("clock.model.debt_ns", debt_);
    ASTRA_PROFILE_COUNT("clock.model.slew_ppm", slewPpm_);
    ASTRA_PROFILE_COUNT("clock.model.rejected", 0);
    return true;
}

/// Publish an estimate at current local time after validation and extrapolation to consumption.
/// Return whether the external estimate was accepted.
bool Clock::publish(const Clock::Estimate& estimate) {

    ASTRA_PROFILE_SCOPE("common.clock.Clock.publish");
    // Serialize anchor, residual, and qualification state; default entry points sample only after acquiring this lock.
    ASTRA_PROFILE_BEGIN(profileLock292, "common.clock.Clock.publish.wait.lock");
    std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock292);
    return observe(estimate, Clock::Elapsed::now());
}

/// Publish at an explicitly supplied local coordinate for deterministic phase injection.
/// Return whether estimate was accepted at local.
bool Clock::publish(const Clock::Estimate& estimate, ElapsedTime local) {

    ASTRA_PROFILE_SCOPE("common.clock.Clock.publish");
    // Serialize anchor, residual, and qualification state; default entry points sample only after acquiring this lock.
    ASTRA_PROFILE_BEGIN(profileLock300, "common.clock.Clock.publish.wait.lock");
    std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock300);
    return observe(estimate, local);
}

/// Revoke reference qualification while retaining local time and finite-deadline capability.
/// Subsequent valid samples may restore quality without clearing published time.
void Clock::revoke() {
    // Serialize anchor, residual, and qualification state; default entry points sample only after acquiring this lock.
    std::lock_guard lock(mutex_);
    trusted_ = false;
}
} // namespace astra
