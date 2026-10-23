// Deliver Catalog watch state through bounded snapshot and incremental feeds.
#include "catalog_feed.hpp"

// Explicitly instantiates the type-safe Catalog feed, sharing queue/authentication/cancellation implementation.
template class astra::Downstream<astra::Catalog>;
