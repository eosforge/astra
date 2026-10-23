// Supply suspend-inclusive elapsed time and independently bounded precision sampling.
#include "../clock_precision.hpp"
#include "ticks.hpp"
#include <astra/clock.hpp>

#include <Windows.h>

namespace astra {
ElapsedTime Clock::Elapsed::now() {

    // Interrupt time includes sleep and hibernation; unbiased time does not.
    ULONGLONG ticks{};
    QueryInterruptTimePrecise(&ticks);
    return time_point(duration(windows::nanoseconds(ticks)));
}

std::uint64_t elapsedPrecisionNanoseconds(std::stop_token stop) {

    // GetTickCount64 is an independent, coarse budget source, not the sampled counter.
    const auto started = GetTickCount64();
    return measureClockPrecision([] { return Clock::Elapsed::now().time_since_epoch().count(); },
                                 [&] {
                                     if (stop.stop_requested()) {
                                         throw std::runtime_error("Clock precision cancelled");
                                     }
                                     return GetTickCount64() - started < 200;
                                 },
                                 100);
}
} // namespace astra
