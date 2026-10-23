// Adapt public Ephemeris observations to the private streaming reader lifecycle.
#pragma once
#include "selection.hpp"
#include "watching.hpp"

namespace comet::detail {
/// Private network core instantiated only in observing.cpp.
extern template class Watching<Selection>;
} // namespace comet::detail
