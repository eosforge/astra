// Adapt public Catalog subscriptions to the private streaming reader lifecycle.
#pragma once
#include "subscription.hpp"
#include "watching.hpp"

namespace comet::detail {
/// Private network core instantiated only in subscribing.cpp.
extern template class Watching<Subscription>;
} // namespace comet::detail
