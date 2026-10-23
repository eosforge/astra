// Validate native conversion boundaries, cancellation and process handler ownership.
#include "check.hpp"
#include "random.hpp"
#include "signals.hpp"
#include "windows/ticks.hpp"
#include <astra/clock.hpp>

#include <array>
#include <csignal>
#include <iostream>
#include <limits>
#include <stop_token>

namespace {
/// Exercise exact conversion boundaries independently of the host uptime.
void conversion() {

    using astra::windows::nanoseconds;
    constexpr auto limit = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) / 100;
    CHECK(nanoseconds(0) == 0);
    CHECK(nanoseconds(1) == 100);
    CHECK(nanoseconds(limit) == static_cast<std::int64_t>(limit * 100));
    for (const auto value : {limit + 1, std::numeric_limits<std::uint64_t>::max()}) {
        bool rejected = false; // Reject instead of wrapping to a negative coordinate.
        try {
            static_cast<void>(nanoseconds(value));
        } catch (const std::overflow_error&) {
            rejected = true;
        }
        CHECK(rejected);
    }
}

/// A pre-cancelled sampler cannot publish a precision result.
void timing() {

    const auto first = astra::Clock::Elapsed::now();
    CHECK(first.time_since_epoch().count() >= 0);
    CHECK(astra::Clock::Elapsed::now() >= first);
    std::stop_source stop; // No sleep is needed to exercise cancellation.
    stop.request_stop();
    bool rejected = false;
    try {
        static_cast<void>(astra::elapsedPrecisionNanoseconds(stop.get_token()));
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Fill only the requested span; this smoke check makes no statistical entropy claim.
void entropy() {

    std::array<std::uint8_t, 34> bytes{}; // End guards must survive native API writes.
    bytes.front() = 0x12;
    bytes.back() = 0x34;
    astra::random(std::span(bytes).subspan(1, 32));
    astra::random({});
    CHECK(bytes.front() == 0x12 && bytes.back() == 0x34);
}

/// Verify a latched cooperative request and restoration after destroying its owner.
void signals() {

    const auto previous = std::signal(SIGTERM, SIG_IGN);
    CHECK(previous != SIG_ERR);
    {
        astra::Signals owner;
        CHECK(!owner.requested());
        CHECK(std::raise(SIGTERM) == 0);
        CHECK(owner.requested());
#ifdef _WIN32
        bool rejected = false; // A second owner must not reset the first owner's request.
        try {
            astra::Signals duplicate;
        } catch (const std::logic_error&) {
            rejected = true;
        }
        CHECK(rejected && owner.requested());
#endif
    }
    CHECK(std::signal(SIGTERM, previous) == SIG_IGN);
}
} // namespace

/// Execute native boundary checks only through the explicitly selected test target.
int main() {

    try {
        conversion();
        timing();
        entropy();
        signals();
        std::cout << "PASS native platform boundaries\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
