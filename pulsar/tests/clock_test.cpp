// Verify Pulsar physical-reference qualification and calibrated clock behavior.
#include "check.hpp"
#include "physical_clock.hpp"

#include <atomic>
#include <iostream>

using namespace astra;
using namespace std::chrono_literals;

#ifdef ASTRA_CLOCK_SAMPLE_TEST
/// Exercise test-only native wrappers before starting any physical-reference workers.
void samples();
#endif

namespace {

/// Poll every 10 ms for at most 10 monotonic seconds, then fail.
static void waitUntil(auto&& predicate) {

    const auto end = Steady::now() + 10s;
    while (Steady::now() < end) {
        if (predicate()) {
            return;
        }
        std::this_thread::sleep_for(10ms);
    }
    throw std::runtime_error("Physical reference did not reach expected state");
}

} // namespace

int main() {

    try {
#ifdef ASTRA_CLOCK_SAMPLE_TEST
        samples();
#endif
        /// Fault modes exist only in the injected test callback; production exposes no system-quality bypass.
        enum class Mode {

            /// Return no physical reference so synchronization cannot be established.
            Missing,

            /// Return the advancing reference with 400 ms uncertainty.
            Valid,

            /// Move the reference ten seconds forward to exercise discontinuity rejection.
            Jumped,

            /// Move the reference ten seconds backward without permitting local time to regress.
            Reversed,

            /// Throw from the injected reference callback to exercise holdover.
            Failed,

            /// Exceed the 500 ms uncertainty ceiling by one nanosecond.
            Uncertain
        };

        std::atomic mode{Mode::Missing};

        const auto reference = [&]() -> std::optional<Clock::Estimate> {
            const auto current = mode.load();
            if (current == Mode::Missing) {
                return std::nullopt;
            }
            if (current == Mode::Failed) {
                throw std::runtime_error("Injected reference failure");
            }

            const auto local = Clock::Elapsed::now();

            const auto correction = current == Mode::Jumped ? 10s : current == Mode::Reversed ? -10s
                                                                                              : 0s;

            const auto time = Clock::Time(1'800'000'000s) + local.time_since_epoch() + correction;
            // Use 400 ms normal uncertainty and 500 ms + 1 ns excess uncertainty to exercise the physical-reference threshold.
            return Clock::Estimate{time, local, current == Mode::Uncertain ? 500'000'001U : 400'000'000U, 0};
        };
        {

            Source source(reference);
            waitUntil([&] { return source.precision() != 0; });
            CHECK(!source.now());
            mode.store(Mode::Valid);
            waitUntil([&] {
                const auto value = source.now();
                return value && value->synchronized;
            });

            const auto initial = *source.now();
            CHECK(initial.time >= Clock::Time(1'800'000'000s));
            mode.store(Mode::Failed);
            waitUntil([&] {
                const auto value = source.now();
                return value && !value->synchronized;
            });
            CHECK(source.now()->time >= initial.time);
            CHECK(source.now()->ready && source.now()->deadlineAfter(1s));
            mode.store(Mode::Valid);
            waitUntil([&] { return source.now()->synchronized; });

            for (const auto jumped : {Mode::Jumped, Mode::Reversed}) {

                const auto before = *source.now();

                const auto started = Clock::Elapsed::now();
                mode.store(jumped);
                waitUntil([&] { return !source.now()->synchronized; });

                const auto after = *source.now();

                const auto elapsed = Clock::Elapsed::now() - started;
                CHECK(after.time >= before.time && after.uncertaintyNanoseconds >= 9'000'000'000ULL);
                // Allow scheduling jitter, but published elapsed time must follow local elapsed time instead of jumping ten seconds.
                CHECK(after.time - before.time < elapsed + 100ms);
                CHECK(after.ready && after.deadlineAfter(1s) == after.time + 1s);
                mode.store(Mode::Valid);
                waitUntil([&] { return source.now()->synchronized; });
            }
            mode.store(Mode::Uncertain);
            waitUntil([&] { return !source.now()->synchronized; });
            CHECK(source.now()->time >= initial.time);
            CHECK(source.now()->ready && source.now()->deadlineAfter(1s));
        }

        // An empty provider must fail construction instead of running indefinitely without a reference.
        bool rejected = false;
        try {

            Source invalid(Source::Provider{});
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
        // A restarted Pulsar uses the same Unix epoch, without a random era or process-relative zero point.
        mode.store(Mode::Valid);

        const auto start = Clock::Elapsed::now();

        Source restarted(reference);
        waitUntil([&] {
            const auto value = restarted.now();
            return value && value->synchronized;
        });

        const auto now = *restarted.now();

        const auto end = Clock::Elapsed::now();
        CHECK(now.time >= Clock::Time(1'800'000'000s) + start.time_since_epoch() - 20ms);
        CHECK(now.time <= Clock::Time(1'800'000'000s) + end.time_since_epoch() + 20ms);
        std::cout << "PASS physical reference readiness, fault recovery, slew and stable Unix restart\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
