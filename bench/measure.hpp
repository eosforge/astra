// Collect benchmark timing and allocation measurements without entering production targets.
#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

/// Benchmark-only statistics, excluded from production libraries; callers own scenario isolation and workload reporting.
class Measure {
public:
    /// Use this process's monotonic clock without requiring synchronized physical time.
    using Clock = std::chrono::steady_clock;

    /// Parse bounded unsigned decimal arguments completely before narrowing; reject signs, trailing data and overflow.
    static std::uint64_t number(std::string_view text, std::uint64_t minimum, std::uint64_t maximum);

    /// Sort finite samples and emit JSON after timing; count is successful acknowledgments and seconds covers the whole window.
    /// Samples are nanoseconds; an empty set has no latency distribution, not zero-valued percentiles.
    static void report(std::string_view name, std::vector<std::int64_t> samples, double seconds, std::size_t count);

    /// Run a fixed-count single-thread closed-loop microbenchmark; action must validate success and make its result observable.
    static void run(std::string_view name, std::size_t count, auto&& action) {

        std::vector<std::int64_t> samples(count); // Preallocate all timing samples to keep capacity growth outside the hot path.
        const auto begin = Clock::now();          // Include timing overhead in throughput without subtracting an estimated cost.
        for (std::size_t index = 0; index < count; ++index) {
            const auto start = Clock::now();
            action(index);
            samples[index] = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start).count();
        }
        const auto seconds = std::chrono::duration<double>(Clock::now() - begin).count();
        report(name, std::move(samples), seconds, count);
    }

    /// An operation failure invalidates the sample and is reported by main.
    static void require(bool condition);
};
