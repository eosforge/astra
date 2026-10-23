// Verify calibration, slew, uncertainty, and deadline behavior with controlled time inputs.
#include "check.hpp"
#include "clock_filter.hpp"
#include "clock_precision.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <iostream>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace astra;
using namespace std::chrono_literals;

namespace {

/// Injected coarse clock stays equal for 4096 reads; wait for actual edges and reject a false 1 ns report without host-precision assumptions.
static void testPrecisionProbe() {

    for (const std::int64_t quantum : {1'000'000, 15'000'000}) {
        // Synthetic read count, initially zero, incremented by read and checked by an independent budget callback.
        std::uint64_t reads = 0;
        // Measured coarse-clock step must equal quantum, not the false 1 ns lower report.
        const auto measured = measureClockPrecision([&] { return static_cast<std::int64_t>(reads++ / 4096) * quantum; }, [&] { return reads < 200'000; }, 1);
        CHECK(measured == static_cast<std::uint64_t>(quantum) && reads > 4096);
    }

    // Fast read cost cannot lower system-reported resolution.
    std::int64_t fast = 0;
    CHECK(measureClockPrecision([&] { return fast += 20; }, [&] { return fast < 100'000; }, 1000) == 1000);

    // Models two nanoseconds per read with 15.6 ms output ticks; observation window uses independent elapsed time.
    // More than 2^22 reads may still succeed, independently of host CPU speed or sleeps.
    std::int64_t elapsed = 0;
    // Fast-reader/coarse-output case may exceed the former fixed loop cap.
    const auto coarse = measureClockPrecision([&] { return (elapsed += 2) / 15'600'000 * 15'600'000; }, [&] { return elapsed < 64'000'000; }, 1);
    CHECK(coarse == 15'600'000 && elapsed / 2 > (1U << 22));

    // Stalled clocks and only two edges cannot fall back silently to reported precision; budget is independent of measured time.
    for (const bool partlyAdvancing : {false, true}) {
        // Synthetic read count, initially zero, incremented by read and checked by an independent budget callback.
        std::uint64_t reads = 0;
        // Initially false; set only on the expected exception so silent fallback cannot pass.
        bool rejected = false;
        try {
            static_cast<void>(measureClockPrecision(
                [&] {
                    // Preincrement sample index generates stalled or two-edge invalid observations.
                    const auto sample = reads++;
                    return partlyAdvancing ? static_cast<std::int64_t>(std::min(sample, std::uint64_t{2})) : std::int64_t{0};
                },
                [&] { return reads < 2048; }, 1));
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        CHECK(rejected && reads >= 2048 && reads <= 2176);
    }

    // Reject reversed readings immediately; signed wrap must not become valid large precision.
    std::int64_t backwards = 100;
    // Initially false; set only on the expected exception so silent fallback cannot pass.
    bool rejected = false;
    try {
        static_cast<void>(measureClockPrecision([&] { return --backwards; }, [] { return true; }, 1));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);

    // Actual cancellation is effective at loop entry without waiting 200 ms or changing system clock settings.
    std::stop_source cancellation;
    cancellation.request_stop();
    rejected = false;
    try {
        static_cast<void>(elapsedPrecisionNanoseconds(cancellation.get_token()));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Cover precision admission and independent cancellation budgets using one callback instantiation.
static void precision() {

    /// Distinguish invalid configuration from unusable monotonic observations.
    enum class Error {
        /// The requested lower bound is outside 1 ns..20 ms.
        Argument,
        /// Sampling cannot supply three supported forward edges.
        Reading
    };
    /// Express exactly one measured result or classified failure.
    using Outcome = std::expected<std::uint64_t, Error>;

    /// Own a finite trace and literal expectations derived from the documented sampling contract.
    struct Entry {
        /// Identify the independent boundary in the native output.
        std::string_view name;
        /// Hold the final value after this finite sequence is consumed.
        std::vector<std::int64_t> samples;
        /// Bound supported precision from below in nanoseconds.
        std::uint64_t minimum;
        /// Grant this many 128-read batches independently of sampled clock values.
        unsigned batches;
        /// Require a literal precision or an exact exception category.
        Outcome expected;
        /// Require the total number of read-callback executions, including the initial anchor.
        std::size_t reads;
        /// Require exact cancellation-budget callback executions.
        unsigned checks;
    };

    // A strictly advancing 33-reading trace reaches the documented 32-edge early stop.
    std::vector<std::int64_t> edges(33);
    std::iota(edges.begin(), edges.end(), std::int64_t{0});
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    const std::array entries{
        Entry{"zero-minimum", {0}, 0, 1, std::unexpected(Error::Argument), 0, 0},
        Entry{"excess-minimum", {0}, 20'000'001, 1, std::unexpected(Error::Argument), 0, 0},
        Entry{"maximum-minimum", {0}, UINT64_MAX, 1, std::unexpected(Error::Argument), 0, 0},
        Entry{"negative-anchor", {-1}, 1, 1, std::unexpected(Error::Reading), 1, 0},
        Entry{"minimum-anchor", {INT64_MIN}, 1, 1, std::unexpected(Error::Reading), 1, 0},
        Entry{"backward-edge", {100, 99}, 1, 1, std::unexpected(Error::Reading), 2, 1},
        Entry{"negative-edge", {0, -1}, 1, 1, std::unexpected(Error::Reading), 2, 1},
        Entry{"cancelled", {0}, 1, 0, std::unexpected(Error::Reading), 1, 1},
        Entry{"stalled", {0}, 1, 1, std::unexpected(Error::Reading), 129, 2},
        Entry{"two-edges", {0, 1, 2}, 1, 1, std::unexpected(Error::Reading), 129, 2},
        Entry{"three-edges", {0, 1, 2, 3}, 1, 1, 1, 129, 2},
        Entry{"best-edge", {0, 2, 7, 10}, 1, 1, 2, 129, 2},
        Entry{"reported-floor", {0, 2, 7, 10}, 3, 1, 3, 129, 2},
        Entry{"maximum-supported", {0, 20'000'000, 40'000'000, 60'000'000}, 20'000'000, 1, 20'000'000, 129, 2},
        Entry{"unsupported-edges", {0, 20'000'001, 40'000'002, 60'000'003}, 1, 1, std::unexpected(Error::Reading), 129, 2},
        Entry{"coordinate-ceiling", {maximum - 3, maximum - 2, maximum - 1, maximum}, 1, 1, 1, 129, 2},
        Entry{"edge-budget", edges, 1, 1, 1, 33, 1},
        Entry{"edge-budget-floor", edges, 1000, 1, 1000, 33, 1},
    };
    for (const auto& entry : entries) {
        CHECK(!entry.samples.empty());
        // Reads plateau after the fixed trace; only the separate callback can end sampling.
        std::size_t reads = 0;
        unsigned checks = 0;
        Outcome actual = std::unexpected(Error::Reading);
        try {
            actual = measureClockPrecision([&] { return entry.samples[std::min(reads++, entry.samples.size() - 1)]; }, [&] { return checks++ < entry.batches; }, entry.minimum);
        } catch (const std::invalid_argument&) {
            actual = std::unexpected(Error::Argument);
        } catch (const std::runtime_error&) {
            actual = std::unexpected(Error::Reading);
        }
        CHECK(actual == entry.expected);
        CHECK(reads == entry.reads);
        CHECK(checks == entry.checks);
        std::cout << "ASTRA-CLOCK-PRECISION {\"case\":\"" << entry.name << "\",\"reads\":" << reads << ",\"checks\":" << checks << "}\n";
    }
}

/// Wraps nanoseconds in local elapsed-time coordinates without actual clock reads.
static ElapsedTime local(std::chrono::nanoseconds value) {
    return ElapsedTime(value);
}

/// Wraps nanoseconds in Unix coordinates, keeping both test reference frames explicit.
static Clock::Time epoch(std::chrono::nanoseconds value) {
    return Clock::Time(value);
}

/// Creates unixTime observation at at, with zero-default uncertainty and fixed zero RTT.
static Clock::Estimate observation(std::chrono::nanoseconds at, std::chrono::nanoseconds unixTime, std::uint64_t uncertainty = 0) {
    return {epoch(unixTime), local(at), uncertainty, 0};
}

/// Check literal wire boundaries, preserving selection and sample admission after invalid observations.
static void boundaries() {

    /// Four timestamps and remote quality supplied by an independently specified fixture.
    struct Sample {
        /// Local send coordinate in unsigned nanoseconds.
        std::uint64_t sent;
        /// Remote receive coordinate in unsigned Unix nanoseconds.
        std::uint64_t arrived;
        /// Remote send coordinate in unsigned Unix nanoseconds.
        std::uint64_t replied;
        /// Local receive coordinate, including deliberately negative examples.
        std::chrono::nanoseconds received;
        /// Remote clock resolution in nanoseconds.
        std::uint64_t precision = 1;
        /// Remote uncertainty in nanoseconds.
        std::uint64_t uncertainty = 0;
        /// Explicit reference qualification supplied by the peer.
        bool synchronized = true;
    };

    // The signed coordinate ceiling is a literal boundary, independent of Filter's implementation.
    constexpr auto maximum = std::numeric_limits<std::int64_t>::max();
    // A zero-delay, finite sample provides an independently fixed selection to protect on rejection.
    const Sample ordinary{100, 1000, 1000, 100ns};
    // No fixture computes its expected verdict from a production guard or helper.
    const std::array rejected = {
        Sample{100, 1000, 1000, 100ns, 1, 0, false},
        Sample{100, 1000, 1000, 100ns, 0},
        Sample{100, 1000, 1000, 100ns, 20'000'001},
        Sample{100, 1000, 1000, 100ns, UINT64_MAX},
        Sample{100, 1000, 1000, 100ns, 1, 500'000'001},
        Sample{100, 1000, 1000, 100ns, 1, UINT64_MAX},
        Sample{UINT64_MAX, 1000, 1000, 100ns},
        Sample{100, UINT64_MAX, UINT64_MAX, 100ns},
        Sample{100, 1000, UINT64_MAX, 100ns},
        Sample{100, 1000, 1000, -1ns},
        Sample{100, 1000, 1000, std::chrono::nanoseconds::min()},
        Sample{101, 1000, 1000, 100ns},
        Sample{100, 1000, 999, 100ns},
        Sample{0, 1000, 1000, 200'000'001ns},
        Sample{0, 1000, 200'001'001, 200ms, 20'000'000},
        Sample{100, 1000, 1005, 100ns},
        Sample{0, static_cast<std::uint64_t>(maximum), static_cast<std::uint64_t>(maximum), 1ns},
    };
    // Invoke the real input boundary without changing fixture values or calling private implementation helpers.
    const auto observe = [](Filter& filter, const Sample& sample) {
        return filter.observe(sample.sent, sample.arrived, sample.replied, local(sample.received), sample.precision, sample.uncertainty, sample.synchronized);
    };
    // Compare every observable field; retaining only the selected time could conceal damaged quality state.
    const auto same = [](const std::optional<Clock::Estimate>& first, const std::optional<Clock::Estimate>& second) {
        return first && second && first->time == second->time && first->sampled == second->sampled && first->uncertaintyNanoseconds == second->uncertaintyNanoseconds && first->rttNanoseconds == second->rttNanoseconds;
    };
    for (const auto& sample : rejected) {
        // Rejection must not count toward the three-sample threshold or poison a fresh filter's recovery.
        Filter empty;
        CHECK(!observe(empty, sample));
        CHECK(!empty.result());
        CHECK(observe(empty, ordinary));
        CHECK(observe(empty, ordinary));
        CHECK(!empty.result());
        CHECK(observe(empty, ordinary));
        CHECK(empty.result() && empty.result()->time == epoch(1000ns));

        // A selected batch must retain its complete result across repeated rejection and remain usable.
        Filter selected;
        for (unsigned count = 0; count < 3; ++count) {
            CHECK(observe(selected, ordinary));
        }
        const auto before = selected.result();
        CHECK(before && before->time == epoch(1000ns) && before->uncertaintyNanoseconds == 4 && before->rttNanoseconds == 1);
        for (unsigned count = 0; count < 2; ++count) {
            CHECK(!observe(selected, sample));
            CHECK(same(before, selected.result()));
        }
        CHECK(observe(selected, ordinary));
        CHECK(same(before, selected.result()));
    }

    /// Accepted wire examples carry literal expected time, delay and quality rather than a duplicate algorithm.
    struct Case {
        /// Fixed valid wire input.
        Sample sample;
        /// Expected selected Unix time in nanoseconds.
        std::chrono::nanoseconds time;
        /// Expected network delay, with the minimum local resolution applied.
        std::uint64_t delay;
        /// Expected complete quality budget in nanoseconds.
        std::uint64_t uncertainty;
    };

    const std::array accepted = {
        Case{{100, 1000, 1000, 100ns, 20'000'000}, 1000ns, 1, 20'000'003},
        Case{{100, 1000, 1000, 100ns, 1, 500'000'000}, 1000ns, 1, 500'000'004},
        Case{{0, 1000, 1000, 200ms}, 100'001'000ns, 200'000'000, 100'300'003},
        Case{{0, 1000, 200'001'000, 200ms}, 200'001'000ns, 1, 300'004},
        Case{{100, 1000, 1004, 100ns}, 1002ns, 1, 4},
        Case{{0, static_cast<std::uint64_t>(maximum - 1), static_cast<std::uint64_t>(maximum - 1), 2ns}, std::chrono::nanoseconds(maximum), 2, 5},
        Case{{static_cast<std::uint64_t>(maximum - 1), 0, 0, std::chrono::nanoseconds(maximum)}, 1ns, 1, 5},
        Case{{0, 0, 0, 0ns}, 0ns, 1, 4},
    };
    for (const auto& input : accepted) {
        Filter filter;
        for (unsigned count = 0; count < 3; ++count) {
            CHECK(observe(filter, input.sample));
        }
        const auto result = filter.result();
        CHECK(result && result->time == epoch(input.time));
        CHECK(result->sampled == local(input.sample.received));
        CHECK(result->rttNanoseconds == input.delay && result->uncertaintyNanoseconds == input.uncertainty);
    }

    // Constructor rejection is separate from remote precision, and does not obtain physical clock samples.
    const std::array resolutions = {std::pair{std::uint64_t{0}, true}, std::pair{std::uint64_t{1}, false}, std::pair{std::uint64_t{20'000'000}, false}, std::pair{std::uint64_t{20'000'001}, true}, std::pair{UINT64_MAX, true}};
    for (const auto& [precision, invalid] : resolutions) {
        bool refused = false;
        try {
            Filter filter(precision);
            CHECK(!filter.result());
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        CHECK(refused == invalid);
    }
    std::cout << "ASTRA-FILTER rejected=" << rejected.size() << " accepted=" << accepted.size() << " configuration=" << resolutions.size() << '\n';
}

/// Deterministic four-timestamp filtering, minimum samples, quantization tolerance, and error thresholds.
static void testFilter() {

    // Default local precision 1 ns, initially no samples; fewer than three valid observations produce no result.
    Filter filter;
    CHECK(!filter.result());
    CHECK(filter.observe(100, 1110, 1120, local(130ns), 1, 0, true));
    CHECK(filter.observe(200, 1202, 1204, local(206ns), 1, 5, true));
    CHECK(!filter.result());
    CHECK(filter.observe(300, 1310, 1320, local(330ns), 1, 0, true));
    // Must choose minimum valid network delay while preserving its receive time and full uncertainty.
    const auto best = filter.result();
    CHECK(best && best->time == epoch(1206ns) && best->rttNanoseconds == 4 && best->sampled == local(206ns));
    CHECK(best->uncertaintyNanoseconds == 11);
    CHECK(!filter.observe(0, 0, 0, local(0ns), 1, 0, false));
    CHECK(!filter.observe(10, 11, 9, local(20ns), 1, 0, true));
    CHECK(!filter.observe(30, 11, 12, local(20ns), 1, 0, true));
    CHECK(!filter.observe(0, 0, 100, local(20ns), 1, 0, true));
    CHECK(!filter.observe(0, 0, 0, local(200'000'001ns), 1, 0, true));
    CHECK(!filter.observe(UINT64_MAX, 0, 0, local(20ns), 1, 0, true));
    CHECK(!filter.observe(0, UINT64_MAX, UINT64_MAX, local(20ns), 1, 0, true));
    CHECK(filter.observe(0, 0, 0, local(20ns), 1, 400'000'000, true));
    CHECK(filter.observe(0, 0, 0, local(20ns), 1, 500'000'000, true));
    CHECK(!filter.observe(0, 0, 0, local(20ns), 1, 500'000'001, true));

    // 15 ms local quantization; negative delay is tolerated only within the explicit error budget.
    Filter coarse(15'000'000);
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(coarse.observe(100, 1000, 21000, local(100ns), 1, 0, true));
    }
    CHECK(coarse.result()->rttNanoseconds == 15'000'000 && coarse.result()->uncertaintyNanoseconds == 22'500'002);
    CHECK(!coarse.observe(100, 0, 30'000'003, local(100ns), 1, 0, true));
    CHECK(!coarse.observe(100, 1000, 21000, local(100ns), 0, 0, true));
    CHECK(!coarse.observe(100, 1000, 21000, local(100ns), 20'000'001, 0, true));
    // A 200 ms RTT includes both endpoint frequency errors and server slewing; the former 500 ppm budget is insufficient.
    Filter drifting;
    for (unsigned i = 0; i < 3; ++i) {
        CHECK(drifting.observe(0, 1000, 100'101'000, local(100ms), 1, 0, true));
    }
    CHECK(drifting.result()->rttNanoseconds == 1 && drifting.result()->uncertaintyNanoseconds == 150'004);
}

/// Deterministic bidirectional slew continuity, step-size independence, and observation replacement.
static void testContinuity() {

    for (const auto sign : {-1, 1}) {
        // Independent default slew clock, initially without an epoch anchor.
        Clock clock;
        CHECK(!clock.now(local(0ns)));
        CHECK(clock.publish(observation(0ns, 100s), local(0ns)));
        CHECK(clock.publish(observation(1s, 101s + sign * 10ms), local(1s)));
        // New observation causes no immediate jump; only one millisecond is corrected after one second.
        CHECK(clock.now(local(1s))->time == epoch(101s));
        CHECK(clock.now(local(2s))->time == epoch(102s + sign * 1ms));
        CHECK(clock.now(local(11s))->time == epoch(111s + sign * 10ms));
        CHECK(clock.now(local(12s))->time == epoch(112s + sign * 10ms));
    }

    // Many small steps and one large step preserve the same integer remainder, independent of read frequency.
    for (const auto sign : {-1, 1}) {
        // small reads frequently and large advances once over equal time; both consume equal integer slew budget.
        Clock small, large;
        for (auto* clock : {&small, &large}) {
            CHECK(clock->publish(observation(0ns, 100s), local(0ns)));
            CHECK(clock->publish(observation(1ns, 100s + 1ns + sign * 10ms), local(1ns)));
        }
        for (std::int64_t ns = 2; ns <= 10001; ++ns) {
            CHECK(small.now(local(std::chrono::nanoseconds(ns))));
        }
        CHECK(small.now(local(10001ns))->time == large.now(local(10001ns))->time);
    }

    // Repeated observations replace offset without directly jumping public time.
    Clock replacement;
    CHECK(replacement.publish(observation(0ns, 100s), local(0ns)));
    CHECK(replacement.publish(observation(1s, 101s + 10ms), local(1s)));
    CHECK(replacement.publish(observation(2s, 102s + 10ms), local(2s)));
    CHECK(replacement.now(local(11s))->time == epoch(111s + 10ms));
    // Concurrent readers advancing after sampling do not invalidate observations; extrapolate at consumption instead of regressing to old T3.
    CHECK(replacement.now(local(12s)));
    CHECK(replacement.publish(observation(11500ms, 111500ms + 10ms), local(12s)));
    CHECK(replacement.now(local(12s))->time == epoch(112s + 10ms));
    CHECK(!replacement.publish(observation(11s, 999s), local(12s)));
    CHECK(replacement.now(local(12s))->time == epoch(112s + 10ms));
}

/// Separates reference quality and local timing, covering exhaustion/reversal; bad samples cannot restore permanent clock failure.
static void testQualityAndLimits() {

    // Independent default slew clock, initially without an epoch anchor.
    Clock clock;
    CHECK(Clock::Reading{}.deadlineAfter(1s) == std::unexpected(Clock::Error::ClockUnready));
    CHECK(!clock.publish(observation(0ns, -1ns), local(0ns)));
    CHECK(!clock.publish(observation(0ns, 100s, 500'000'001), local(0ns)));
    CHECK(!clock.publish(observation(0ns, 100s), local(6s)));
    CHECK(!clock.now(local(6s)));
    CHECK(clock.publish(observation(0ns, 100s), local(0ns)));
    CHECK(clock.now(local(5s))->synchronized);
    CHECK(!clock.now(local(5s + 1ns))->synchronized);
    // Beyond the former five-second threshold, continuous time still creates deadlines without another Pulsar reply.
    const auto offline = clock.now(local(6s));
    CHECK(offline && offline->ready && !offline->synchronized && offline->time == epoch(106s));
    CHECK(offline->deadlineAfter(1s) == epoch(107s));
    CHECK(clock.publish(observation(6s, 106s), local(6s)));
    // Same recovered reading checks valid and negative TTL deadline computation.
    const auto ready = clock.now(local(6s));
    CHECK(ready->ready && ready->synchronized);
    CHECK(ready->deadlineAfter(1s) == epoch(107s));
    CHECK(ready->deadlineAfter(-1ns) == std::unexpected(Clock::Error::InvalidTime));
    clock.revoke();
    // Explicit reference revocation must preserve established local epoch timekeeping.
    const auto revoked = clock.now(local(7s));
    CHECK(revoked->ready && !revoked->synchronized && revoked->time == epoch(107s));
    CHECK(revoked->deadlineAfter(1s) == epoch(108s));
    // Even a large estimate change after source restart affects quality and correction rate only.
    CHECK(clock.publish(observation(8s, 5000s), local(8s)));
    CHECK(clock.now(local(8s))->time == epoch(108s) && !clock.now(local(8s))->synchronized);
    CHECK(clock.now(local(8s))->deadlineAfter(1s) == epoch(109s));
    CHECK(clock.now(local(9s))->time == epoch(109s + 1ms));
    CHECK(clock.now(local(9s))->uncertaintyNanoseconds >= 4'891'000'000'000ULL);

    // Fixed 500 ms synchronization threshold; excessive uncertainty loses quality while calibrated local time still creates finite deadlines.
    Clock boundary;
    CHECK(boundary.publish(observation(0ns, 100s, 500'000'000), local(0ns)));
    CHECK(boundary.now(local(0ns))->synchronized);
    CHECK(!boundary.now(local(1ns))->synchronized);
    CHECK(boundary.now(local(1ns))->deadlineAfter(1s) == epoch(101s + 1ns));
    // 400 ms uncertainty lies below the current 500 ms readiness threshold.
    Clock relaxed;
    CHECK(relaxed.publish(observation(0ns, 100s, 400'000'000), local(0ns)));
    CHECK(relaxed.now(local(0ns))->ready && relaxed.now(local(0ns))->synchronized);

    // One-week elapsed jump still permits second-scale leases; sample age is not added to TTL.
    Clock suspended;
    CHECK(suspended.publish(observation(0ns, 100s), local(0ns)));
    CHECK(suspended.now(local(24h * 7))->time == epoch(100s + 24h * 7));
    CHECK(!suspended.now(local(24h * 7))->synchronized);
    CHECK(suspended.now(local(24h * 7))->deadlineAfter(1s) == epoch(101s + 24h * 7));
    // Starts just below the nanosecond upper bound to exercise deadline/timekeeping exhaustion.
    Clock overflow;
    CHECK(overflow.publish({Clock::Time::max() - 1ns, local(0ns), 0, 0}, local(0ns)));
    CHECK(overflow.now(local(0ns))->deadlineAfter(2ns) == std::unexpected(Clock::Error::Exhausted));
    CHECK(overflow.now(local(1ns))->time == Clock::Time::max());
    CHECK(!overflow.now(local(2ns)));
    CHECK(!overflow.publish(observation(3ns, 100s), local(3ns)));
    // Reversed local counter must become permanent infrastructure failure, not an ordinary reference update.
    Clock backwards;
    CHECK(backwards.publish(observation(1s, 100s), local(1s)));
    CHECK(!backwards.now(local(0ns)));
    CHECK(!backwards.publish(observation(2s, 102s), local(2s)));
    CHECK(!backwards.now(local(3s)));

    // A newer remote sample cannot conceal local regression after a successful intervening read.
    Clock publication;
    CHECK(publication.publish(observation(0ns, 100s), local(0ns)));
    CHECK(publication.now(local(2s))->time == epoch(102s));
    CHECK(!publication.publish(observation(1s, 101s), local(1s)));
    CHECK(!publication.now(local(3s)));
    CHECK(!publication.publish(observation(4s, 104s), local(4s)));
    publication.revoke();
    CHECK(!publication.now(local(5s)));
    for (const auto rate : {0U, 1001U}) {
        // Initially false; set only on the expected exception so silent fallback cannot pass.
        bool rejected = false;
        try {
            Clock invalid(rate);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }
}

/// Concurrent publication and reading must never regress public Unix time.
static void testConcurrentReading() {

    // Independent default slew clock, initially without an epoch anchor.
    Clock clock;
    // Actual BOOTTIME origin anchors synthetic Unix extrapolation.
    const auto origin = Clock::Elapsed::now();
    CHECK(clock.publish({epoch(1'800'000'000s), origin, 0, 0}));
    // Initially false; writer completion stops reader loops.
    std::atomic_bool finished{};
    // Borrows clock, origin, and finished; explicit join precedes their stack destruction.
    std::jthread writer([&] {
        for (unsigned i = 0; i < 1000; ++i) {
            // Actual sample may trail reader advancement; publish extrapolates at consumption.
            const auto sample = Clock::Elapsed::now();
            static_cast<void>(clock.publish({epoch(1'800'000'000s) + (sample - origin), sample, 0, 0}));
        }
        finished.store(true);
    });
    // Previous public time, initially Unix zero, for sequential monotonicity assertions.
    auto previous = Clock::Time{};
    do {
        // Current reading must exist and be at least previous.
        const auto now = clock.now();
        CHECK(now && now->time >= previous);
        previous = now->time;
    } while (!finished.load());
    writer.join();
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        testPrecisionProbe();
        precision();
        boundaries();
        testFilter();
        testContinuity();
        testQualityAndLimits();
        testConcurrentReading();
        std::cout << "PASS Unix clock filtering, continuous slew, holdover, quality and concurrent reading\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
