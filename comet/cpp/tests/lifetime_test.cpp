// Verify cancellation draining and ownership of asynchronous SDK activities.
#include "check.hpp"
#include "lifetime.hpp"

#include <iostream>

namespace {
using namespace std::chrono_literals;
using comet::detail::Lifetime;

/// Calls the actual platform clock to verify linking and nonnegative, nondecreasing output; never changes system time or suspends the host.
void platform() {
    const auto first = Lifetime::now();  // First clock read; failure must not masquerade as zero.
    const auto second = Lifetime::now(); // Adjacent reads may be equal but cannot go backward.
    CHECK(first && second && *first >= 0 && *second >= *first);
}

/// Models send, retry, late response, suspend, and new UUID without sleeps; every boundary uses integer milliseconds.
void budget() {

    Lifetime lifetime(1s);
    CHECK(!lifetime.ready(1000) && lifetime.due(1000));
    CHECK(lifetime.confirm(1000));
    CHECK(lifetime.ready(1999) && !lifetime.ready(2000));
    CHECK(lifetime.confirm(1000) && !lifetime.ready(2001)); // Repeated success does not restart the lease at response arrival.
    CHECK(lifetime.confirm(900) && !lifetime.ready(2001));  // A late older attempt cannot replace a newer confirmation.
    CHECK(!lifetime.ready(std::nullopt) && !lifetime.ready(999));
    CHECK(lifetime.due(8 * 24 * 60 * 60 * 1000LL)); // One week of suspend yields one due state only.
    CHECK(lifetime.confirm(3000) && lifetime.ready(3500));
    lifetime.reset();
    CHECK(!lifetime.ready(3500) && lifetime.due(3500));
    CHECK(!lifetime.confirm(-1) && !lifetime.confirm(INT64_MAX));
    CHECK(lifetime.confirm(INT64_MAX - 1000));
    CHECK(lifetime.ready(INT64_MAX - 1) && !lifetime.ready(INT64_MAX));
}

/// Minimum-TTL jitter still schedules in hundreds of milliseconds; boundaries produce neither zero periods nor integer overflow.
void cadence() {

    Lifetime lifetime(1s);
    CHECK(lifetime.confirm(1000));
    for (std::size_t seed = 0; seed != 1000; ++seed) {
        lifetime.spread(seed);
        const auto interval = lifetime.delay(1000).count();
        CHECK(interval >= 300 && interval <= 366);
        CHECK(!lifetime.due(1000 + interval - 1) && lifetime.due(1000 + interval));
        CHECK(lifetime.delay(1'000'000) == 0ms);
    }
    for (const auto ttl : {0ms, -1ms, 999ms, 600001ms}) {
        bool rejected{}; // Invalid private configuration must fail explicitly during initialization.
        try {
            Lifetime invalid(ttl);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
    }
}
} // namespace

int main() {
    try {
        platform();
        budget();
        cadence();
        std::cout << "local lease budget cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
