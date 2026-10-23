// Deliver Ephemeris watch state through bounded snapshot and incremental feeds.
#pragma once
#include "downstream.hpp"
#include "ephemeris_edition.hpp"

namespace astra {
/// Ephemeris selects its own record encoding; shared implementation owns streams, backpressure, authentication, and cancellation.
class Ephemeris::Feed final : public Downstream<Ephemeris> {
public:
    /// Inherits construction/lifetime contracts without extra state.
    using Downstream<Ephemeris>::Downstream;
};
} // namespace astra
