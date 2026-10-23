// Verify storage deadline behavior against explicit calibrated-clock state.
#include "check.hpp"
#include "store.hpp"

#include <array>
#include <iostream>

using namespace astra;
using namespace std::chrono_literals;

namespace {

/// Check literal constructor boundaries without deriving expected results from Store's predicate.
static void configuration() {

    /// A fixed input and its independently specified rejection result.
    struct Case {
        /// Positive timer resolution, or an explicitly invalid boundary.
        std::chrono::nanoseconds interval;
        /// Nonnegative history age; zero disables history retention.
        Steady::duration retention;
        /// Optional nonnegative Unix origin, independent of physical time.
        std::optional<Clock::Time> initial;
        /// Only invalid_argument satisfies an expected configuration rejection.
        bool rejected;
    };

    // These twelve cases cover absent/zero/extreme valid values and each invalid term independently.
    const std::array cases = {
        Case{1ns, 0ns, {}, false},
        Case{1ns, 0ns, Clock::Time{}, false},
        Case{1ns, 0ns, Clock::Time(1ns), false},
        Case{1ns, 0ns, Clock::Time::max(), false},
        Case{1ns, Steady::duration::max(), {}, false},
        Case{std::chrono::nanoseconds::max(), 0ns, {}, false},
        Case{0ns, 0ns, {}, true},
        Case{-1ns, 0ns, {}, true},
        Case{1ns, -1ns, {}, true},
        Case{1ns, 0ns, Clock::Time(-1ns), true},
        Case{1ns, 0ns, Clock::Time::min(), true},
        Case{0ns, -1ns, Clock::Time(-1ns), true},
    };
    for (const auto& input : cases) {
        // Catch only the documented configuration error; unexpected exceptions fail the executable.
        bool rejected = false;
        try {
            Store store(0, input.retention, input.interval, input.initial);
            CHECK(store.version() == 0);
            CHECK(store.snapshot()->data.empty());
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected == input.rejected);
    }
}

/// Verify time rejection preserves both live data and a previously captured snapshot.
static void inputs() {

    /// Observable outcomes distinguish invalid time from a missing Unix anchor.
    enum class Outcome {
        /// The complete write commits once.
        Accepted,
        /// A negative Unix time is rejected before changing state.
        Invalid,
        /// A finite deadline needs an initialized Unix coordinate.
        Unanchored
    };

    /// Literal deadline examples specify both initialized and uninitialized behavior.
    struct Case {
        /// An absent deadline is permanent; other values use Unix nanoseconds.
        std::optional<Clock::Time> deadline;
        /// Expected outcome when the Store has an explicit epoch-zero anchor.
        Outcome anchored;
        /// Expected outcome before the first successful tick.
        Outcome unanchored;
    };

    // Zero and the maximum Unix value are legal deadlines; negativity remains invalid in both states.
    const std::array cases = {
        Case{{}, Outcome::Accepted, Outcome::Accepted},
        Case{Clock::Time{}, Outcome::Accepted, Outcome::Unanchored},
        Case{Clock::Time(1ns), Outcome::Accepted, Outcome::Unanchored},
        Case{Clock::Time::max(), Outcome::Accepted, Outcome::Unanchored},
        Case{Clock::Time(-1ns), Outcome::Invalid, Outcome::Invalid},
        Case{Clock::Time::min(), Outcome::Invalid, Outcome::Invalid},
    };
    for (const bool anchored : {false, true}) {
        for (const auto& input : cases) {
            // Each case owns its data, timer state and snapshots, without a real clock wait.
            Store store(0, 0ns, 1ns, anchored ? std::optional(Clock::Time{}) : std::nullopt);
            store.put("existing", {7});
            const auto before = store.snapshot();
            const auto expected = anchored ? input.anchored : input.unanchored;
            auto outcome = Outcome::Accepted;
            try {
                store.put("new", {9}, input.deadline);
            } catch (const std::invalid_argument&) {
                outcome = Outcome::Invalid;
            } catch (const std::logic_error&) {
                outcome = Outcome::Unanchored;
            }
            CHECK(outcome == expected);

            // The old view stays unchanged on acceptance too; rejection must preserve the live version.
            const auto after = store.snapshot();
            CHECK(before->version == 1 && before->data.size() == 1);
            CHECK(*before->data.at("existing").value == Store::Buffer{7});
            CHECK(after->version == (expected == Outcome::Accepted ? 2 : 1));
            CHECK(store.version() == after->version);
            CHECK(*after->data.at("existing").value == Store::Buffer{7});
            CHECK(after->data.contains("new") == (expected == Outcome::Accepted));
            if (expected == Outcome::Accepted) {
                CHECK(*after->data.at("new").value == Store::Buffer{9});
                CHECK(after->data.at("new").deadline == input.deadline);
            }
        }

        // Neither an initialized nor an uninitialized timer may accept a negative tick.
        for (const auto time : {Clock::Time(-1ns), Clock::Time::min()}) {
            Store store(0, 0ns, 1ns, anchored ? std::optional(Clock::Time{}) : std::nullopt);
            store.put("existing", {7});
            const auto before = store.snapshot();
            bool rejected = false;
            try {
                store.tick(time);
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            CHECK(rejected);
            CHECK(store.version() == 1 && store.snapshot()->data.size() == 1);
            CHECK(*store.snapshot()->data.at("existing").value == Store::Buffer{7});
            CHECK(before->version == 1 && *before->data.at("existing").value == Store::Buffer{7});

            // A rejected tick must not poison later explicit initialization and a valid finite write.
            store.tick(Clock::Time{});
            store.put("finite", {9}, Clock::Time(1ns));
            CHECK(store.version() == 2 && store.snapshot()->data.size() == 2);
        }
    }
}

/// Wraps nanoseconds as local elapsed time for deterministic calibration.
static ElapsedTime local(std::chrono::nanoseconds time) {
    return ElapsedTime(time);
}

/// Wraps nanoseconds as Unix time without introducing a process epoch number.
static Clock::Time epoch(std::chrono::nanoseconds time) {
    return Clock::Time(time);
}

/// Injects time at at with zero uncertainty/RTT; failed publication asserts.
static void calibrate(Clock& clock, std::chrono::nanoseconds at, std::chrono::nanoseconds time) {
    CHECK(clock.publish({epoch(time), local(at), 0, 0}, local(at)));
}

/// Different local clock origins share one Unix deadline; both Stores must expire at the same business time.
static void testCommonCoordinate() {

    // Calibrate local origins 100 s and 900 s to the same Unix time.
    Clock a, b;
    // Independent Stores retain equal absolute leases, proving deadlines do not depend on local origin.
    Store first, second;
    calibrate(a, 100s, 1'800'000'000s);
    calibrate(b, 900s, 1'800'000'000s);
    first.tick(a.now(local(100s))->time);
    second.tick(b.now(local(900s))->time);
    // One absolute deadline from a ready reading; later reference changes cannot rewrite it.
    const auto deadline = a.now(local(100s))->deadlineAfter(2s);
    CHECK(deadline && b.now(local(900s))->deadlineAfter(2s) == deadline);
    first.put("lease", {1}, *deadline);
    second.put("lease", {1}, *deadline);
    CHECK(first.extract(0).deltas.front().deadline == *deadline);
    CHECK(first.snapshot()->data.at("lease").deadline == *deadline);
    first.tick(a.now(local(101990ms))->time);
    second.tick(b.now(local(901990ms))->time);
    CHECK(first.snapshot()->data.contains("lease") && second.snapshot()->data.contains("lease"));
    first.tick(a.now(local(102s))->time);
    second.tick(b.now(local(902s))->time);
    CHECK(first.snapshot()->data.empty() && second.snapshot()->data.empty());
}

/// Reference steps affect slew and quality only, preserving accepted deadlines and local creation of new leases.
static void testReferenceChange() {

    for (const auto correction : {-10s, 10s}) {
        // Independent epoch clock, default 1000 ppm slew, explicitly anchored by calibrate.
        Clock clock;
        // Default 10 ms Store, initially unanchored and driven by valid clock readings.
        Store store;
        calibrate(clock, 0s, 100s);
        store.tick(clock.now(local(0s))->time);
        // One absolute deadline from a ready reading; later reference changes cannot rewrite it.
        const auto deadline = clock.now(local(0s))->deadlineAfter(5s);
        CHECK(deadline);
        store.put("existing", {1}, *deadline);
        // Retains pre-reference-change values and deadlines for immutability checks.
        const auto snapshot = store.snapshot();
        clock.revoke();
        store.tick(clock.now(local(2s))->time);
        calibrate(clock, 3s, 103s + correction);
        // Continuous reading after reference change; residual offset lowers quality while deadlines still use local continuous time.
        const auto reading = clock.now(local(3s));
        CHECK(reading->time == epoch(103s) && reading->ready && !reading->synchronized);
        CHECK(reading->deadlineAfter(5s) == epoch(108s));
        store.tick(reading->time);
        CHECK(store.snapshot() == snapshot && store.version() == 1);
        CHECK(store.extract(0).deltas.front().deadline == *deadline);
        CHECK(snapshot->data.at("existing").deadline == *deadline);
        // Original deadline remains 105 s in either correction direction; bounded millisecond slew never restores a full TTL.
        store.tick(clock.now(local(4990ms))->time);
        CHECK(store.snapshot()->data.contains("existing"));
        store.tick(clock.now(local(5020ms))->time);
        CHECK(store.snapshot()->data.empty() && store.version() == 2);
        CHECK(snapshot->data.at("existing").deadline == *deadline);
    }
}

/// Existing TTL expires during reference loss; recovery or a new Store cannot renew the original lease implicitly.
static void testHoldoverAndRecovery() {

    // Independent epoch clock, default 1000 ppm slew, explicitly anchored by calibrate.
    Clock clock;
    // Default 10 ms Store, initially unanchored and driven by valid clock readings.
    Store store;
    calibrate(clock, 0s, 100s);
    store.tick(clock.now(local(0s))->time);
    // One absolute deadline from a ready reading; later reference changes cannot rewrite it.
    const auto deadline = clock.now(local(0s))->deadlineAfter(5s);
    CHECK(deadline);
    store.put("expires-offline", {1}, *deadline);
    clock.revoke();
    store.tick(clock.now(local(6s))->time);
    CHECK(store.snapshot()->data.empty());
    calibrate(clock, 7s, 107s);
    CHECK(clock.now(local(7s))->ready && clock.now(local(7s))->synchronized);
    store.tick(clock.now(local(7s))->time);
    CHECK(store.snapshot()->data.empty() && store.version() == 2);
    // A newly calibrated process restoring the same absolute deadline must not restart the original TTL.
    Store restored;
    restored.tick(epoch(106s));
    restored.put("expired", {1}, epoch(105s));
    restored.put("future", {2}, epoch(108s));
    restored.tick(epoch(106010ms));
    CHECK(!restored.snapshot()->data.contains("expired") && restored.snapshot()->data.contains("future"));
    restored.tick(epoch(108s));
    CHECK(restored.snapshot()->data.empty());
}

/// Create/renew during reference loss; unrenewed entries expire and reference recovery changes no committed deadline.
static void testOfflineLeases() {

    // Initially calibrated to Unix 100 s; test explicitly advances all later elapsed time.
    Clock clock;
    // Store carries renewed and unrenewed data at default 10 ms ticks.
    Store store;
    calibrate(clock, 0s, 100s);
    store.tick(epoch(100s));
    store.put("expires", {1}, epoch(130s));
    store.put("renewed", {2}, epoch(130s));
    // Pins both preoutage deadlines; renewal/deletion must preserve the old view.
    const auto snapshot = store.snapshot();
    clock.revoke();

    // Renew for 30 s at outage ages 10, 20, and 30 s without accepting new reference samples.
    for (const auto elapsed : {10s, 20s, 30s}) {
        // One owned clock reading per round; ready stays true while synchronized is false.
        const auto reading = clock.now(local(elapsed));
        CHECK(reading && reading->ready && !reading->synchronized);
        store.tick(reading->time);
        CHECK(store.snapshot()->data.contains("renewed"));
        // Deadline adds 30 s to current time only, never to the old sample or previous deadline.
        const auto deadline = reading->deadlineAfter(30s);
        CHECK(deadline == epoch(130s + elapsed));
        store.put("renewed", {2}, *deadline);

        if (elapsed == 10s) {
            // Five-second deadline for an entry created during outage; without renewal it expires independently.
            const auto created = reading->deadlineAfter(5s);
            CHECK(created == epoch(115s));
            store.put("created-offline", {3}, *created);
        } else {
            CHECK(!store.snapshot()->data.contains("created-offline"));
        }
        CHECK(store.snapshot()->data.contains("expires") == (elapsed < 30s));
    }

    calibrate(clock, 31s, 131s);
    CHECK(clock.now(local(31s))->synchronized);
    store.tick(clock.now(local(31s))->time);
    CHECK(store.snapshot()->data.size() == 1);
    CHECK(store.snapshot()->data.at("renewed").deadline == epoch(160s));
    CHECK(snapshot->data.at("expires").deadline == epoch(130s));
    CHECK(snapshot->data.at("renewed").deadline == epoch(130s));
    store.tick(clock.now(local(59990ms))->time);
    CHECK(store.snapshot()->data.contains("renewed"));
    store.tick(clock.now(local(60s))->time);
    CHECK(store.snapshot()->data.empty());
}

/// Covers unanchored finite-write rejection, initial Unix anchoring, snapshot deadline isolation, and negative time.
static void testInitializationAndMetadata() {

    // Default 10 ms Store, initially unanchored and driven by valid clock readings.
    Store store;
    store.put("permanent", {1});
    // Set only for expected configuration/state exceptions; silent conversion to permanent data must fail.
    bool rejected = false;
    try {
        store.put("unanchored", {2}, epoch(100s));
    } catch (const std::logic_error&) {
        rejected = true;
    }
    CHECK(rejected && store.version() == 1);
    // Initial anchor near the actual year must not replay ticks from 1970.
    const auto now = epoch(1'800'000'000s);
    store.tick(now);
    store.put("finite", {2}, now + 5s);
    // Pins the version before renewal; later writes change deadlines in new views only.
    const auto before = store.snapshot();
    CHECK(!before->data.at("permanent").deadline);
    CHECK(before->data.at("finite").deadline == now + 5s);
    store.put("finite", {3}, now + 10s);
    CHECK(store.snapshot()->data.at("finite").deadline == now + 10s);
    CHECK(before->data.at("finite").deadline == now + 5s);
    CHECK(store.extract(2).deltas.front().deadline == now + 10s);
    store.put("finite", {4});
    CHECK(!store.snapshot()->data.at("finite").deadline);
    store.tick(now + 20s);
    CHECK(store.snapshot()->data.size() == 2);
    rejected = false;
    try {
        store.put("negative", {}, epoch(-1ns));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected && !store.snapshot()->data.contains("negative"));
    rejected = false;
    try {
        store.tick(epoch(-1ns));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    CHECK(rejected);
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        configuration();
        inputs();
        testCommonCoordinate();
        testReferenceChange();
        testHoldoverAndRecovery();
        testOfflineLeases();
        testInitializationAndMetadata();
        std::cout << "PASS single Unix deadlines, continuous correction, holdover and snapshot metadata\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
