// Maintain copy-on-write indexed snapshots with explicit reader and draft ownership.
#pragma once
#include "pages.hpp"
#include <astra/clock.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace astra {
/// Single-value row for existing KV/Almanac, never a substitute for native Catalog or Ephemeris records.
struct Cell {
    /// Immutable payload ownership; null means no internal payload, while valid zero-byte values remain non-null.
    std::shared_ptr<const std::vector<std::uint8_t>> value;
    /// Fixed Unix deadline, empty for permanent values; always empty for Almanac.
    std::optional<Clock::Time> deadline{};
};

/// Retains Index::Record/Buffer/Value/View API while sharing paging algorithms with actual native records.
using Index = Pages<Cell>;
} // namespace astra
