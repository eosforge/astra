// Keep test assertions active in Release and report failed expressions with source locations.
#pragma once

#include <atomic>
#include <cstdio>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>

namespace astra::test {
/// Count successful checks in every test thread without allocating inside fault-injection regions.
struct Checks {
    /// Successful assertions across all test threads; failed assertions do not increment the count.
    std::atomic<unsigned long long> hits{};

    /// Delimit observations even after an assertion interrupts a streamed trace; the collector checks the native exit status.
    ~Checks() {
        std::fprintf(stdout, "\nASTRA-CHECKS {\"hits\":%llu}\n", hits.load(std::memory_order_relaxed));
    }
};

/// Process-wide assertion counter, emitted at normal process teardown.
inline Checks checks;

/// Keep the same assertion in Release and Debug; failures retain the caller's expression and location.
inline void check(bool condition, std::string_view expression, std::source_location location = std::source_location::current()) {

    if (!condition) {
        throw std::runtime_error(std::string(location.file_name()) + ':' + std::to_string(location.line()) + ": " + std::string(expression));
    }
    checks.hits.fetch_add(1, std::memory_order_relaxed);
}
} // namespace astra::test

// Evaluate once while retaining expression text; static_cast accepts explicit expected and smart-pointer conversions.
#define CHECK(condition) ::astra::test::check(static_cast<bool>(condition), #condition)
