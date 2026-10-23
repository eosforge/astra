// Linux suspend-inclusive time and timerfd sampling budget.
#include "../clock_precision.hpp"
#include <astra/clock.hpp>

#include <cerrno>
#include <limits>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

namespace astra {
namespace {
/// Largest representable signed nanosecond coordinate.
constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
} // namespace

// Include suspend in local sample age and elapsed windows.
// Reject failed or unrepresentable native readings.
ElapsedTime Clock::Elapsed::now() {

    // The zeroed output buffer is not itself a valid sample.
    timespec value{};
    if (::clock_gettime(CLOCK_BOOTTIME, &value) != 0 || value.tv_sec < 0 || value.tv_nsec < 0 || value.tv_nsec >= 1'000'000'000 || value.tv_sec > (maximum - value.tv_nsec) / 1'000'000'000) {
        throw std::runtime_error("Cannot read elapsed clock");
    }
    return time_point(duration(value.tv_sec * 1'000'000'000 + value.tv_nsec));
}

std::uint64_t elapsedPrecisionNanoseconds(std::stop_token stop) {

    // Bound edge sampling by an independent kernel timer, not CPU loop count.
    struct Timer {
        /// Own this sampling attempt's nonblocking timer; -1 means acquisition failed.
        int descriptor = ::timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);

        /// Close on success, cancellation and failure without transferring ownership.
        ~Timer() {

            if (descriptor >= 0) {
                ::close(descriptor);
            }
        }
    } timer;

    // Arm a one-shot 200 ms budget with no recurring timer.
    itimerspec budget{};
    budget.it_value.tv_nsec = 200'000'000;
    if (timer.descriptor < 0) {
        throw std::runtime_error("Cannot start clock precision budget");
    }

    // The advertised resolution is a floor, not a substitute for edge measurement.
    timespec resolution{};
    if (::clock_getres(CLOCK_BOOTTIME, &resolution) != 0 || resolution.tv_sec != 0 || resolution.tv_nsec <= 0 || resolution.tv_nsec > 20'000'000) {
        throw std::runtime_error("Unsupported elapsed clock resolution");
    }
    if (::timerfd_settime(timer.descriptor, 0, &budget, nullptr) != 0) {
        throw std::runtime_error("Cannot arm clock precision budget");
    }
    return measureClockPrecision([] { return elapsedNanoseconds(Clock::Elapsed::now()); },
                                 [&] {
                                     if (stop.stop_requested()) {
                                         throw std::runtime_error("Clock precision cancelled");
                                     }

                                     // Observe expiry without advancing any business clock.
                                     std::uint64_t expirations{};
                                     // EAGAIN means time remains; EINTR permits the next bounded attempt.
                                     const auto result = ::read(timer.descriptor, &expirations, sizeof(expirations));
                                     if (result == static_cast<ssize_t>(sizeof(expirations))) {
                                         return false;
                                     }
                                     if (result < 0 && (errno == EAGAIN || errno == EINTR)) {
                                         return true;
                                     }
                                     throw std::runtime_error("Cannot read clock precision budget");
                                 },
                                 static_cast<std::uint64_t>(resolution.tv_nsec));
}

} // namespace astra
