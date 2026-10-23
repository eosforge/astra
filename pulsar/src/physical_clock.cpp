// Read and qualify the host physical-clock reference for calibrated Pulsar time.
#include "physical_clock.hpp"

#include <astra/profile.hpp>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <sys/timex.h>
#include <time.h>

namespace astra {
/// Samples a physical reference; unsynchronized kernels or excessive sampling windows yield no sample.
std::optional<Clock::Estimate> Source::sample() {

    ASTRA_PROFILE_SCOPE("clock.kernel.sample");
    // Bracket quality and wall-clock queries so uncertainty includes scheduling delay; BOOTTIME includes suspension in age checks.
    const auto before = Clock::Elapsed::now();
    // modes=0 makes adjtimex read-only; no system clock changes are submitted.
    timex state{};

    const auto status = ::adjtimex(&state);

    timespec wall{};
    const auto result = ::clock_gettime(CLOCK_REALTIME, &wall); // Record probes after the sampling window, excluding diagnostic output latency from kernel sampling delay.
    const auto after = Clock::Elapsed::now();
    ASTRA_PROFILE_VALUE("clock.kernel.status", status);
    ASTRA_PROFILE_VALUE("clock.kernel.flags", state.status);
    ASTRA_PROFILE_VALUE("clock.kernel.maxerror_us", state.maxerror);
    ASTRA_PROFILE_VALUE("clock.kernel.esterror_us", state.esterror);
    ASTRA_PROFILE_VALUE("clock.kernel.offset", state.offset);
    ASTRA_PROFILE_COUNT("clock.kernel.offset_unit_ns", (state.status & STA_NANO) != 0 ? 1 : 1000);
    ASTRA_PROFILE_VALUE("clock.kernel.elapsed_ns", elapsedNanoseconds(after));
    ASTRA_PROFILE_VALUE("clock.kernel.window_ns", (after - before).count());
    if (status < 0 || status == TIME_ERROR || (state.status & (STA_UNSYNC | STA_CLOCKERR)) != 0 || state.maxerror < 0 || state.esterror < 0 || result != 0) {
        ASTRA_PROFILE_COUNT("clock.kernel.rejected", 1);
        return std::nullopt;
    }

    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    if (after < before || after - before > std::chrono::milliseconds(20) || wall.tv_sec < 0 || wall.tv_nsec < 0 || wall.tv_nsec >= 1'000'000'000 || wall.tv_sec > (maximum - wall.tv_nsec) / 1'000'000'000) {
        ASTRA_PROFILE_COUNT("clock.kernel.rejected", 2);
        return std::nullopt;
    }
    ASTRA_PROFILE_VALUE("clock.kernel.unix_ns", wall.tv_sec * 1'000'000'000 + wall.tv_nsec);

    // Kernel error fields use microseconds; STA_NANO determines offset units. Bound values before conversion or absolute-value operations.
    const auto errorMicroseconds = std::max(state.maxerror, state.esterror);

    const auto offsetLimit = static_cast<long>(clockUncertaintyLimitNanoseconds / ((state.status & STA_NANO) != 0 ? 1U : 1000U));
    if (errorMicroseconds > static_cast<long>(clockUncertaintyLimitNanoseconds / 1000) || state.offset < -offsetLimit || state.offset > offsetLimit) {
        ASTRA_PROFILE_COUNT("clock.kernel.rejected", 3);
        return std::nullopt;
    }

    const auto offset = static_cast<std::uint64_t>(state.offset < 0 ? -state.offset : state.offset);
    // Uncertainty sums kernel error, residual offset, and the full sampling window in nanoseconds.
    const auto uncertainty = static_cast<std::uint64_t>(errorMicroseconds) * 1000 + offset * ((state.status & STA_NANO) != 0 ? 1U : 1000U) + static_cast<std::uint64_t>((after - before).count());
    ASTRA_PROFILE_COUNT("clock.kernel.uncertainty_ns", uncertainty);
    if (uncertainty > clockUncertaintyLimitNanoseconds) {
        ASTRA_PROFILE_COUNT("clock.kernel.rejected", 4);
        return std::nullopt;
    }
    ASTRA_PROFILE_COUNT("clock.kernel.rejected", 0);

    // The wall-clock sample lies within before..after; charge the full window without assuming midpoint execution.
    return Clock::Estimate{Clock::Time(std::chrono::nanoseconds(wall.tv_sec * 1'000'000'000 + wall.tv_nsec)), after, uncertainty, 0};
}

Source::Source(Provider provider) : provider_(std::move(provider)) {

    if (!provider_) {
        throw std::invalid_argument("Physical clock requires a reference provider");
    }
    worker_ = std::jthread([this](std::stop_token stop) { run(stop); });
}

Source::~Source() {

    worker_.request_stop();
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::optional<Clock::Reading> Source::now() const {
    return clock_.now();
}

std::uint64_t Source::precision() const noexcept {
    return precision_.load(std::memory_order_acquire);
}

/// Sampling failure revokes reference synchronization while the calibrated clock continues under holdover rules.
void Source::run(std::stop_token stop) noexcept {

    try {
        while (!stop.stop_requested()) {
            try {
                ASTRA_PROFILE_SCOPE("clock.source.poll");
                if (precision() == 0) {
                    precision_.store(elapsedPrecisionNanoseconds(stop), std::memory_order_release);
                }
                if (stop.stop_requested()) {
                    break;
                }

                auto sample = provider_();
                if (!stop.stop_requested() && sample) {
                    // Include local clock quantization; nanosecond encoding does not imply nanosecond accuracy.
                    if (sample->uncertaintyNanoseconds > clockUncertaintyLimitNanoseconds) {
                        sample.reset();
                    } else {
                        sample->uncertaintyNanoseconds += precision();
                    }
                }
                const bool accepted = !stop.stop_requested() && sample && clock_.publish(*sample);
                ASTRA_PROFILE_COUNT("clock.source.available", sample.has_value());
                ASTRA_PROFILE_COUNT("clock.source.accepted", accepted);
                if (!accepted) {
                    clock_.revoke();
                }
            } catch (...) {
                ASTRA_PROFILE_SCOPE("clock.source.failure");
                ASTRA_PROFILE_COUNT("clock.source.exception", 1);
                clock_.revoke();
            }

            // Cancellable waiting lets destruction stop without waiting a full sampling period.
            std::unique_lock lock(waitMutex_);
            condition_.wait_for(lock, stop, std::chrono::seconds(1), [] { return false; });
        }
    } catch (...) {
        // Wait failures revoke reference qualification instead of terminating the process with a background exception.
    }
    clock_.revoke();
}
} // namespace astra
