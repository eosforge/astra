// Deliver Ephemeris watch state through bounded snapshot and incremental feeds.
#include "ephemeris_feed.hpp"

// Explicit instantiation of the shared stream engine without duplicating domain rules.
template class astra::Downstream<astra::Ephemeris>;
