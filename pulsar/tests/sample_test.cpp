// Exercise physical-reference qualification through deterministic, test-only native call wrappers.
#include "check.hpp"
#include "physical_clock.hpp"

#include <array>
#include <cerrno>
#include <limits>
#include <optional>
#include <stdexcept>
#include <sys/timex.h>
#include <time.h>

namespace {
/// One bounded kernel observation; no host settings or process-global clock functions are replaced.
struct Sample {
    /// Native quality fields; modes remains zero.
    timex kernel{};
    /// Representable Unix epoch sample.
    timespec wall{1'800'000'000, 0};
    /// Explicit before/after BOOTTIME coordinates.
    std::array<timespec, 2> local{{{7, 0}, {7, 1000}}};
    /// Result returned by the readonly quality query.
    int status = TIME_OK;
    /// Wall-clock query result; negative means failure.
    int wallResult = 0;
    /// Local query index to fail, or -1 for neither.
    int localFailure = -1;
    /// Main-thread BOOTTIME calls observed in this scope.
    unsigned elapsedCalls = 0;
    /// Main-thread realtime calls observed in this scope.
    unsigned wallCalls = 0;
    /// Readonly quality queries observed in this scope.
    unsigned qualityCalls = 0;
    /// Reject accidental nonzero adjtimex modes.
    bool readonly = true;

    /// Use literal contract inputs instead of deriving the oracle from production thresholds.
    Sample() {
        kernel.maxerror = 10'000;
        kernel.esterror = 2'000;
    }

    /// Call the production sampler once and always release the thread-local injection scope.
    std::optional<astra::Clock::Estimate> read();
};

/// Only the invoking test thread can consume a synthetic observation.
thread_local Sample* active = nullptr;

std::optional<astra::Clock::Estimate> Sample::read() {

    CHECK(active == nullptr);

    /// Restore the real sampling-call path after the scoped fault probe exits.
    struct Reset {
        /// Restore the real-call path on success and exception alike.
        ~Reset() {
            active = nullptr;
        }
    } reset;

    active = this;
    auto result = astra::Source::sample(); // Exercise the actual implementation, including native conversions.
    CHECK(readonly && elapsedCalls == 2 && wallCalls == 1 && qualityCalls == 1);
    return result;
}
} // namespace

/// Original linker target outside the injected main-thread scope.
extern "C" int __real_adjtimex(timex*) noexcept;
/// Original time source for workers and runtime code.
extern "C" int __real_clock_gettime(clockid_t, timespec*) noexcept;

/// Supply explicit quality fields only while a synchronous sample owns this thread's injection scope.
extern "C" int __wrap_adjtimex(timex* value) noexcept {

    if (!active) {
        return __real_adjtimex(value);
    }
    ++active->qualityCalls;
    active->readonly = active->readonly && value->modes == 0;
    *value = active->kernel;
    return active->status;
}

/// Keep runtime/background clocks real; inject only the two native sources used by the active sample.
extern "C" int __wrap_clock_gettime(clockid_t clock, timespec* value) noexcept {

    if (!active) {
        return __real_clock_gettime(clock, value);
    }
    if (clock == CLOCK_REALTIME) {
        ++active->wallCalls;
        *value = active->wall;
        return active->wallResult;
    }
    if (clock == CLOCK_BOOTTIME) {
        const auto index = active->elapsedCalls++; // Never read beyond the two explicit observation endpoints.
        if (index >= active->local.size() || static_cast<int>(index) == active->localFailure) {
            errno = EIO;
            return -1;
        }
        *value = active->local[index];
        return 0;
    }
    return __real_clock_gettime(clock, value);
}

/// Cover each kernel-quality rejection independently, exact accepted boundaries and combined-error overflow.
void samples() {

    using namespace std::chrono_literals;
    Sample baseline; // Ordinary quality fields plus the full one-microsecond query window.
    const auto initial = baseline.read();
    CHECK(initial && initial->time == astra::Clock::Time(1'800'000'000s));
    CHECK(initial->sampled == astra::Clock::Elapsed::time_point(7s + 1000ns));
    CHECK(initial->uncertaintyNanoseconds == 10'001'000);

    const auto rejects = [](auto change) {
        Sample value; // Every negative case differs from an accepted baseline, avoiding masked prerequisites.
        change(value);
        CHECK(!value.read());
    };
    rejects([](auto& value) { value.status = -1; });
    rejects([](auto& value) { value.status = TIME_ERROR; });
    rejects([](auto& value) { value.kernel.status = STA_UNSYNC; });
    rejects([](auto& value) { value.kernel.status = STA_CLOCKERR; });
    rejects([](auto& value) { value.kernel.maxerror = -1; });
    rejects([](auto& value) { value.kernel.esterror = -1; });
    rejects([](auto& value) { value.wallResult = -1; });
    rejects([](auto& value) { value.local[1] = {6, 999'999'999}; });
    rejects([](auto& value) { value.local[1].tv_nsec = 20'000'001; });
    rejects([](auto& value) { value.wall.tv_sec = -1; });
    rejects([](auto& value) { value.wall.tv_nsec = -1; });
    rejects([](auto& value) { value.wall.tv_nsec = 1'000'000'000; });
    rejects([](auto& value) { value.kernel.maxerror = 500'001; });
    rejects([](auto& value) { value.kernel.esterror = 500'001; });
    rejects([](auto& value) { value.kernel.offset = std::numeric_limits<long>::min(); });
    rejects([](auto& value) { value.kernel.offset = std::numeric_limits<long>::max(); });

    Sample window; // Exactly twenty milliseconds is accepted and charged in full.
    window.local[1].tv_nsec = 20'000'000;
    const auto bounded = window.read();
    CHECK(bounded && bounded->uncertaintyNanoseconds == 30'000'000);
    Sample maximum; // Last representable signed nanosecond, followed by the first overflowing coordinate.
    maximum.wall = {9'223'372'036, 854'775'807};
    const auto last = maximum.read();
    CHECK(last && last->time.time_since_epoch().count() == 9'223'372'036'854'775'807LL);
    rejects([](auto& value) { value.wall = {9'223'372'036, 854'775'808}; });

    for (const bool estimated : {false, true}) {
        Sample error; // Either native error field can independently determine the quality upper bound.
        error.local[1] = error.local[0];
        if (estimated) {
            error.kernel.esterror = 500'000;
        } else {
            error.kernel.maxerror = 500'000;
        }
        const auto exact = error.read();
        CHECK(exact && exact->uncertaintyNanoseconds == 500'000'000);
    }
    for (const bool nano : {false, true}) {
        for (const long sign : {-1L, 1L}) {
            Sample offset; // Offset units follow STA_NANO; both signs share an inclusive 500 ms boundary.
            offset.kernel.maxerror = offset.kernel.esterror = 0;
            offset.local[1] = offset.local[0];
            offset.kernel.status = nano ? STA_NANO : 0;
            offset.kernel.offset = sign * (nano ? 500'000'000L : 500'000L);
            const auto exact = offset.read();
            CHECK(exact && exact->uncertaintyNanoseconds == 500'000'000);
            rejects([&](auto& value) {
                value.kernel.status = nano ? STA_NANO : 0;
                value.kernel.offset = sign * (nano ? 500'000'001L : 500'001L);
            });
        }
    }
    Sample total; // Individually legal fields must still fit the combined error budget.
    total.kernel.maxerror = 250'000;
    total.kernel.offset = -249'999;
    const auto exact = total.read();
    CHECK(exact && exact->uncertaintyNanoseconds == 500'000'000);
    rejects([](auto& value) {
        value.kernel.maxerror = 250'000;
        value.kernel.offset = -249'999;
        value.local[1].tv_nsec = 1001;
    });

    for (const int failed : {0, 1}) {
        Sample unavailable; // BOOTTIME failure is an infrastructure exception, never an empty accepted estimate.
        unavailable.localFailure = failed;
        bool rejected = false;
        try {
            static_cast<void>(unavailable.read());
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        CHECK(rejected && active == nullptr && unavailable.elapsedCalls == static_cast<unsigned>(failed + 1));
    }
}
