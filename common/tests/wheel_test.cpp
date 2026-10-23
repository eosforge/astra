// Verify timing-wheel scheduling and expiry using caller-controlled time advancement.
#include "check.hpp"
#include "wheel.hpp"

#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <type_traits>

namespace {
/// Independent default five-level wheels and nodes per case, without wall time or execution-order dependence.
using Timer = astra::Wheel<>;
/// Store's four-level, 1024-slot wheel has separate coverage.
using WideTimer = astra::Wheel<4, 10>;

/// requires checks template availability; invalid configurations must fail before instantiation.
template <std::size_t Levels, std::size_t Bits>
concept ValidWheel = requires { typename astra::Wheel<Levels, Bits>; };

static_assert(!ValidWheel<0, 8> && !ValidWheel<3, 0> && !ValidWheel<1, 11> && !ValidWheel<9, 8> && !ValidWheel<7, 10>);
static_assert(ValidWheel<1, 1> && ValidWheel<3, 8> && ValidWheel<8, 8> && ValidWheel<64, 1>);
static_assert(ValidWheel<1, 9> && ValidWheel<4, 10> && ValidWheel<6, 10>);
static_assert(Timer::limit == 1'099'511'627'775 && astra::Wheel<8, 8>::limit == UINT64_MAX);
static_assert(WideTimer::limit == Timer::limit);
static_assert(!std::is_copy_constructible_v<Timer> && !std::is_move_constructible_v<Timer>);
static_assert(!std::is_copy_assignable_v<Timer> && !std::is_move_assignable_v<Timer>);
static_assert(!std::is_copy_constructible_v<Timer::Node> && !std::is_move_constructible_v<Timer::Node>);
static_assert(!std::is_copy_assignable_v<Timer::Node> && !std::is_move_assignable_v<Timer::Node>);
static_assert(std::is_nothrow_destructible_v<Timer> && std::is_nothrow_destructible_v<Timer::Node>);
static_assert(noexcept(std::declval<Timer&>().schedule(std::declval<Timer::Node&>(), 1)));

/// Timer fires exactly at delay, with zero deferred to next tick; initial covers slot/level boundaries and uint64_t wrap.
template <typename W>
void checkDeadline(std::uint64_t initial, std::uint64_t delay) {

    // Selected logical origin; Node dies before Wheel to check safe automatic unlink.
    W wheel(initial);
    typename W::Node node;
    // Simple-model remaining ticks and actual callback count verify exactly-once expiry.
    const auto effective = std::max(delay, std::uint64_t{1});
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    CHECK(wheel.schedule(node, delay));
    CHECK(node.scheduled());
    for (std::uint64_t elapsed = 1; elapsed <= effective + 1; ++elapsed) {
        wheel.tick([&](auto* value) {
            CHECK(value == &node);
            CHECK(!node.scheduled());
            CHECK(elapsed == effective);
            CHECK(wheel.now() == initial + effective);
            ++calls;
        });
        CHECK(calls == (elapsed >= effective ? 1U : 0U));
    }
}

/// Default configuration covers level boundaries; small configurations exhaust all origins/delays, including maximum delay and highest-level wrap.
void testDeadlines() {

    for (const auto delay : {0U, 1U, 2U, 255U, 256U, 257U, 65'535U, 65'536U, 65'537U}) {
        checkDeadline<Timer>(0, delay);
        checkDeadline<Timer>(253, delay);
        checkDeadline<Timer>(UINT64_MAX - 257, delay);
    }
    for (std::uint64_t initial = 0; initial < 64; ++initial) {
        for (std::uint64_t delay = 0; delay <= astra::Wheel<3, 2>::limit; ++delay) {
            checkDeadline<astra::Wheel<3, 2>>(initial, delay);
        }
    }
    checkDeadline<astra::Wheel<1, 1>>(UINT64_MAX, 1);
    checkDeadline<astra::Wheel<8, 8>>(UINT64_MAX - 1, 3);
    checkDeadline<astra::Wheel<64, 1>>(UINT64_MAX - 1, 3);
    // Narrow slots cover all five cascade levels and maximum delay without 2^32 default ticks.
    for (std::uint64_t initial = 0; initial < 32; ++initial) {
        for (std::uint64_t delay = 0; delay <= astra::Wheel<5, 1>::limit; ++delay) {
            checkDeadline<astra::Wheel<5, 1>>(initial, delay);
        }
    }
    checkDeadline<astra::Wheel<5, 2>>(1000, astra::Wheel<5, 2>::limit);
    // Default slots start near high-bit boundaries and integer wrap to exercise multilevel countr_zero paths.
    for (const auto boundary : {std::uint64_t{1} << 24, std::uint64_t{1} << 32, std::uint64_t{1} << 40}) {
        checkDeadline<Timer>(boundary - 257, 1024);
    }
}

/// Wide wheel covers 1024-slot boundaries, cascades, and wrap; maximum delay checks scheduling/canceling without traversing the whole span.
void testWideDeadlines() {

    for (const auto delay : {0U, 1U, 1023U, 1024U, 1025U}) {
        checkDeadline<WideTimer>(0, delay);
        checkDeadline<WideTimer>(UINT64_MAX - 1025, delay);
    }

    // This Node actually cascades from level three; other high boundaries start nearby to bound test work.
    checkDeadline<WideTimer>(0, (std::uint64_t{1} << 20) + 1);
    for (const auto boundary : {std::uint64_t{1} << 20, std::uint64_t{1} << 30, std::uint64_t{1} << 40}) {
        checkDeadline<WideTimer>(boundary - 1025, 4096);
    }

    // Starts near uint64_t wrap to check maximum legal delay.
    WideTimer wheel(UINT64_MAX - 1024);
    // Stable stack Node for wide-wheel rescheduling and cancellation.
    WideTimer::Node node;
    CHECK(wheel.schedule(node, WideTimer::limit));
    CHECK(!wheel.schedule(node, WideTimer::limit + 1) && node.scheduled());
    WideTimer::cancel(node);
    wheel.tick([](auto*) { CHECK(false); });
    CHECK(!node.scheduled());
}

/// Invalid rescheduling preserves the old plan; valid rescheduling replaces it, and repeated cancel handles bucket head/middle/tail.
void testScheduleAndCancel() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Stable same-bucket hooks for cancellation and callback-order checks.
    std::array<Timer::Node, 3> nodes;
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    CHECK(wheel.schedule(nodes[0], 1));
    CHECK(!wheel.schedule(nodes[0], Timer::limit + 1));
    CHECK(nodes[0].scheduled());
    wheel.tick([&](auto*) { ++calls; });
    CHECK(calls == 1);
    CHECK(wheel.schedule(nodes[0], 1));
    CHECK(wheel.schedule(nodes[0], 2));
    wheel.tick([&](auto*) { ++calls; });
    CHECK(calls == 1);
    wheel.tick([&](auto*) { ++calls; });
    CHECK(calls == 2);

    // Cancel each position independently in a three-node bucket, without assuming callback order.
    for (std::size_t victim = 0; victim < nodes.size(); ++victim) {
        for (auto& node : nodes) {
            CHECK(wheel.schedule(node, 1));
        }
        Timer::cancel(nodes[victim]);
        Timer::cancel(nodes[victim]);
        calls = 0;
        wheel.tick([&](auto* node) {
            CHECK(node != &nodes[victim]);
            ++calls;
        });
        CHECK(calls == 2);
    }
}

/// Canceling another due Node inside a callback takes effect immediately; no saved next pointer may access it later.
void testCallbackCancel() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Stable same-bucket hooks for cancellation and callback-order checks.
    std::array<Timer::Node, 2> nodes;
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    for (auto& node : nodes) {
        CHECK(wheel.schedule(node, 1));
    }
    wheel.tick([&](auto* current) {
        ++calls;
        // The other not-yet-fired Node regardless of actual callback ordering.
        auto& other = current == &nodes[0] ? nodes[1] : nodes[0];
        Timer::cancel(other);
    });
    CHECK(calls == 1 && !nodes[0].scheduled() && !nodes[1].scheduled());
}

/// Callback destroys itself and another due Node; destructor unlink must not access a freed predecessor, including under Sanitizers.
void testCallbackDestroy() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Exclusive heap Nodes destroyed inside callbacks to expose dangling links.
    std::array<std::unique_ptr<Timer::Node>, 2> nodes{std::make_unique<Timer::Node>(), std::make_unique<Timer::Node>()};
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    for (auto& node : nodes) {
        CHECK(wheel.schedule(*node, 1));
    }
    wheel.tick([&](auto* current) {
        ++calls;
        // Current Node is destroyed first to expose other Nodes still referencing its old predecessor address.
        const auto first = current == nodes[0].get() ? 0U : 1U;
        nodes[first].reset();
        nodes[1U - first].reset();
    });
    CHECK(calls == 1 && !nodes[0] && !nodes[1]);
}

/// Current and peer Nodes may reschedule to next tick without looping in this tick or losing future work.
void testCallbackReschedule() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Stable same-bucket hooks for cancellation and callback-order checks.
    std::array<Timer::Node, 2> nodes;
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    for (auto& node : nodes) {
        CHECK(wheel.schedule(node, 1));
    }
    wheel.tick([&](auto*) {
        ++calls;
        for (auto& node : nodes) {
            CHECK(wheel.schedule(node, 0));
        }
    });
    CHECK(calls == 1);
    wheel.tick([&](auto*) { ++calls; });
    CHECK(calls == 3 && !nodes[0].scheduled() && !nodes[1].scheduled());
}

/// Callback exceptions retain remaining queue; next tick finishes the old batch before advancement and never retries the thrown callback automatically.
void testCallbackException() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Stable same-bucket hooks for cancellation and callback-order checks.
    std::array<Timer::Node, 3> nodes;
    // Expires one tick after this batch, detecting premature advancement after exceptions.
    Timer::Node future;
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    // Initially null; records the callback Node consumed before throwing.
    Timer::Node* consumed = nullptr;
    for (auto& node : nodes) {
        CHECK(wheel.schedule(node, 1));
    }
    CHECK(wheel.schedule(future, 2));
    try {
        wheel.tick([&](auto* node) {
            consumed = node;
            ++calls;
            throw 17;
        });
        CHECK(false);
    } catch (int value) {
        CHECK(value == 17);
    }
    CHECK(calls == 1 && wheel.now() == 1 && consumed != nullptr && !consumed->scheduled());
    // Nodes still in ready_ may be canceled outside tick, requiring a valid predecessor address.
    auto& cancelled = consumed == &nodes[0] ? nodes[1] : nodes[0];
    Timer::cancel(cancelled);
    wheel.tick([&](auto* node) {
        CHECK(node != consumed && node != &cancelled);
        CHECK(wheel.now() == (node == &future ? 2U : 1U));
        ++calls;
    });
    CHECK(calls == 3 && wheel.now() == 2);
    for (const auto& node : nodes) {
        CHECK(!node.scheduled());
    }

    // Repeated failure cannot advance beyond unprocessed same-tick Nodes; final recovery advances normally.
    for (auto& node : nodes) {
        CHECK(wheel.schedule(node, 1));
    }
    calls = 0;
    for (std::size_t attempt = 0; attempt < nodes.size(); ++attempt) {
        try {
            wheel.tick([&](auto*) {
                ++calls;
                throw 19;
            });
            CHECK(false);
        } catch (int value) {
            CHECK(value == 19);
        }
        CHECK(calls == attempt + 1 && wheel.now() == 3);
    }
    wheel.tick([](auto*) { CHECK(false); });
    CHECK(wheel.now() == 4);
}

/// Same-wheel recursive tick fails explicitly without corrupting outer guard; later ordinary ticks still work.
void testReentrantTick() {

    // Case-owned zero-origin wheel without wall-clock reads.
    Timer wheel;
    // Stable local Node, never moved while linked.
    Timer::Node node;
    CHECK(wheel.schedule(node, 1));
    // Initially false; set only for expected recursive-advancement failure.
    bool rejected = false;
    wheel.tick([&](auto*) {
        try {
            wheel.tick([](auto*) {});
        } catch (const std::logic_error&) {
            rejected = true;
        }
        CHECK(wheel.now() == 1);
        CHECK(wheel.schedule(node, 1));
    });
    CHECK(rejected);
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    wheel.tick([&](auto*) { ++calls; });
    CHECK(calls == 1 && wheel.now() == 2);
}

/// Node-first destruction unlinks, Wheel-first destruction clears surviving hooks, and same-type Wheels may explicitly transfer a Node.
void testLifetimeAndTransfer() {

    // Outlives the first Wheel to verify destruction clears external hooks.
    Timer::Node survivor;
    {
        // Case-owned zero-origin wheel without wall-clock reads.
        Timer wheel;
        CHECK(wheel.schedule(survivor, 256));
        {
            // Dies before Wheel; automatic cancel must prevent callback.
            Timer::Node temporary;
            CHECK(wheel.schedule(temporary, 1));
        }
        wheel.tick([](auto*) { CHECK(false); });
    }
    CHECK(!survivor.scheduled());
    Timer::cancel(survivor);

    // Zero-origin source wheel has no expiry after transferring survivor.
    Timer first;
    // Starts at 100; after transfer only this Wheel fires survivor.
    Timer second(100);
    CHECK(first.schedule(survivor, 1));
    CHECK(second.schedule(survivor, 1));
    first.tick([](auto*) { CHECK(false); });
    // Actual callback count, initially zero, checked explicitly at each stage.
    std::size_t calls = 0;
    // Move-only callback invokes directly, without std::function or hidden copies.
    second.tick([state = std::make_unique<int>(7), &calls](auto*) mutable {
        CHECK(*state == 7);
        ++calls;
    });
    CHECK(calls == 1 && !survivor.scheduled());

    // Wheel may safely destroy unprocessed ready_ Nodes after callback failure.
    std::array<Timer::Node, 3> pending;
    {
        // Case-owned zero-origin wheel without wall-clock reads.
        Timer wheel;
        for (auto& node : pending) {
            CHECK(wheel.schedule(node, 1));
        }
        try {
            wheel.tick([](auto*) { throw 1; });
        } catch (int) {}
    }
    for (const auto& node : pending) {
        CHECK(!node.scheduled());
    }
}

/// Independent per-tick countdown model checks random schedule/cancel/reschedule results per Node with fixed seed.
template <typename W>
void testModel(std::uint64_t initial, std::uint64_t seed) {

    /// Test Item embeds Node and carries id without expanding production hook size.
    struct Item : W::Node {
        /// Fixed independent-model array index.
        std::size_t id{};
    };

    // Selected logical origin covers hierarchy boundaries and wrap.
    W wheel(initial);
    // Fixed-array owned hooks; each id matches one model entry.
    std::array<Item, 64> items;
    // Independent remaining-tick model; nullopt means unscheduled. seen detects multiple callbacks this tick.
    std::array<std::optional<std::uint64_t>, 64> remaining{};
    // Cleared every tick; a repeated id callback is rejected by the independent model.
    std::array<bool, 64> seen{};
    // Fixed seed makes operation sequence reproducible.
    std::mt19937_64 random(seed);
    // Random delay bound is min(wheel capacity, 1000 ticks).
    const auto limit = std::min(W::limit, std::uint64_t{1000});
    // Model elapsed ticks, initially zero, for actual-wheel coordinate checks.
    std::uint64_t elapsed = 0;
    // Model initialization/check index, independent of callback order.
    for (std::size_t id = 0; id < items.size(); ++id) {
        items[id].id = id;
    }

    // Advances countdown model first, then independently checks actual callbacks and every Node's linked state.
    auto advance = [&] {
        seen.fill(false);
        ++elapsed;
        // Borrows remaining model ticks; empty means unscheduled.
        for (auto& counter : remaining) {
            if (counter) {
                --*counter;
            }
        }
        wheel.tick([&](auto* node) {
            // Recovers stable id from the hook for remaining/seen lookup.
            const auto id = static_cast<Item*>(node)->id;
            CHECK(remaining[id] && *remaining[id] == 0 && !seen[id]);
            seen[id] = true;
        });
        CHECK(wheel.now() == initial + elapsed);
        // Model initialization/check index, independent of callback order.
        for (std::size_t id = 0; id < items.size(); ++id) {
            CHECK(seen[id] == (remaining[id] && *remaining[id] == 0));
            if (seen[id]) {
                remaining[id].reset();
            }
            CHECK(items[id].scheduled() == remaining[id].has_value());
        }
    };
    // 30000 random operations per configuration keep the case bounded.
    for (std::size_t step = 0; step < 30'000; ++step) {
        // Random current array index, always below items.size().
        const auto id = static_cast<std::size_t>(random() % items.size());
        // Operation 0..3: 0/1 schedule, 2 cancel, 3 advance.
        const auto operation = random() % 4;
        if (operation < 2) {
            // Delay 0..limit; zero means next tick.
            const auto delay = random() % (limit + 1);
            CHECK(wheel.schedule(items[id], delay));
            remaining[id] = std::max(delay, std::uint64_t{1});
        } else if (operation == 2) {
            W::cancel(items[id]);
            remaining[id].reset();
        } else {
            advance();
        }
    }

    // After random work, advances until all remaining Nodes expire.
    for (std::uint64_t step = 0; step <= limit; ++step) {
        advance();
    }

    // Checks no model entry retains pending work after draining.
    for (const auto& counter : remaining) {
        CHECK(!counter);
    }
}
} // namespace

/// Isolated process with Release-active assertions; advances logical time only, without services or sleeps.
int main() {

    try {
        testDeadlines();
        testWideDeadlines();
        testScheduleAndCancel();
        testCallbackCancel();
        testCallbackDestroy();
        testCallbackReschedule();
        testCallbackException();
        testReentrantTick();
        testLifetimeAndTransfer();
        testModel<astra::Wheel<1, 4>>(0, 11);
        testModel<astra::Wheel<3, 2>>(61, 22);
        testModel<Timer>(65'530, 33);
        testModel<Timer>(UINT64_MAX - 1024, 44);
        testModel<astra::Wheel<8, 8>>(UINT64_MAX - 1024, 55);
        testModel<astra::Wheel<64, 1>>(UINT64_MAX - 1024, 66);
        testModel<WideTimer>(1020, 77);
        testModel<WideTimer>(UINT64_MAX - 1024, 88);
        std::cout << "Wheel boundary, lifetime, callback and 240000 model operations passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
