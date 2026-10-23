// Measure authoritative Almanac storage operations with explicit workload and result accounting.
#include "almanac.hpp"

#include "measure.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace {
/// Measure one authoritative scope with strict +1 versions, production history budgets and owned-payload API costs.
void run(std::size_t count, std::size_t bytes) {

    astra::Almanac book;                     // Apply deltas only after a valid initial baseline, using production default capacities.
    astra::Almanac::Buffer value(bytes, 42); // The caller owns this payload; apply accepts by value and its copy contributes to the measurement.
    std::vector<std::string> keys(count);    // Construct names outside the timed region.
    auto draft = book.prepare(1);
    for (std::size_t index = 0; index < count; ++index) {
        keys[index] = "key-" + std::to_string(index);
        Measure::require(draft.set(keys[index], value).has_value());
    }
    Measure::require(book.reset(std::move(draft)) == true);

    Measure::run("almanac.find", 20000, [&](std::size_t index) { const auto point = book.find(keys[index % count]); Measure::require(point && point->value && point->value->size() == bytes); });
    Measure::run("almanac.capture", 20000, [&](std::size_t) { const auto view = book.view(); Measure::require(view && view->size() == count); });
    std::uint64_t version = 1; // Advance the scope version once for every valid Apply, including an unchanged value.
    Measure::run("almanac.apply", 20000, [&](std::size_t index) { Measure::require(book.apply(++version, keys[index % count], value) == true); });

    const auto frozen = book.view(); // Retain the old root to measure writes while prior views remain live.
    Measure::require(frozen.has_value());
    Measure::run("almanac.apply_with_view", 20000, [&](std::size_t index) { Measure::require(book.apply(++version, keys[index % count], value) == true); });
    std::size_t visited{}; // Validate outside the lock and update timing.
    frozen->each([&](const auto&, const auto&) { ++visited; });
    Measure::require(visited == count);
    Measure::run("almanac.replay_one", 20000, [&](std::size_t) { const auto replay = book.replay(version - 1); Measure::require(replay && replay->changes.size() == 1); });

    // Full rebuild cost includes payload copies, index construction, atomic replacement and old-state release, not just a root swap.
    Measure::run("almanac.recover", 5, [&](std::size_t) {
        auto candidate = book.prepare(++version);
        for (const auto& key : keys) {
            Measure::require(candidate.set(key, value).has_value());
        }
        Measure::require(book.reset(std::move(candidate)) == true);
    });
}
} // namespace

/// Use the native benchmark's two explicit arguments; capacity/version exceptions invalidate the sample.
int main(int count, char** arguments) {
    try {
        Measure::require(count == 3);
        const auto records = Measure::number(arguments[1], 1, 10000), bytes = Measure::number(arguments[2], 1, 4096); // Keep the finite working set within production defaults and reject trailing argument data.
        run(records, bytes);
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
