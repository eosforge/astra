// Implement benchmark argument validation and measurement reporting.
#include "measure.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <system_error>
#include <utility>

std::uint64_t Measure::number(std::string_view text, std::uint64_t minimum, std::uint64_t maximum) {
    std::uint64_t value{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || value < minimum || value > maximum) {
        throw std::invalid_argument("Invalid unsigned benchmark argument");
    }
    return value;
}

void Measure::report(std::string_view name, std::vector<std::int64_t> samples, double seconds, std::size_t count) {
    std::ranges::sort(samples);
    std::cout << "{\"metric\":\"" << name << "\",\"count\":" << count << ",\"seconds\":" << seconds << ",\"operations_per_second\":" << (seconds > 0 ? static_cast<double>(count) / seconds : 0) << ",\"samples\":" << samples.size();

    // Report nearest-rank percentiles in microseconds for both local operations and RPCs.
    for (const auto& [percentile, value] : {std::pair{"p50_us", 0.5}, {"p95_us", 0.95}, {"p99_us", 0.99}, {"p999_us", 0.999}}) {
        std::cout << ",\"" << percentile << "\":";
        if (samples.empty()) {
            std::cout << "null";
        } else {
            const auto index = static_cast<std::size_t>(std::ceil(value * static_cast<double>(samples.size()))) - 1;
            std::cout << static_cast<double>(samples[index]) / 1000.0;
        }
    }
    std::cout << "}" << std::endl;
}

void Measure::require(bool condition) {
    if (!condition) {
        throw std::runtime_error("Performance operation failed validation");
    }
}
