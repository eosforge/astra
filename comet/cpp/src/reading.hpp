// Adapt public Almanac reads to the private streaming reader lifecycle.
#pragma once
#include "projection.hpp"
#include "watching.hpp"

namespace comet::detail {
/// Private network core instantiated only in reading.cpp.
extern template class Watching<Projection>;
} // namespace comet::detail
