// Deliver Catalog watch state through bounded snapshot and incremental feeds.
#pragma once
#include "catalog_edition.hpp"
#include "downstream.hpp"

namespace astra {
/// Bounded Catalog content stream, separate from Ephemeris messages.
class Catalog::Feed final : public Downstream<Catalog> {
public:
    /// Shares State, Gateway, wakeup, and finite budgets.
    using Downstream<Catalog>::Downstream;
};
} // namespace astra
