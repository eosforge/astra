// Verify Catalog native-state transitions, quotas, and scheduled expiry.
#include "catalog_state.hpp"
#include "check.hpp"
#include "exports.hpp"

#include <array>
#include <atomic>
#include <iostream>
#include <latch>
#include <new>
#include <string>
#include <thread>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Scope;
using State = Catalog::State;

/// Opaque immutable test body; empty text retains nonnull ownership.
Catalog::Value bytes(std::string_view value) {
    return std::make_shared<const Catalog::Buffer>(value.begin(), value.end());
}

/// Version query reads merged watermarks without creating Scopes, independently of expiration/source origin.
void versions() {

    auto now = 1s; // Controlled business time, independent of host wall clock.
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"query", "main"};
    const std::array<std::string_view, 3> keys{"local", "remote", "missing"};
    CHECK(state.versions(scope, keys).value() == std::vector<std::uint64_t>({0, 0, 0}));
    CHECK(state.source().size() == 0);
    CHECK(state.publish(scope, "local", bytes("local"), 7, 1000));
    CHECK(state.admit("remote"));
    CHECK(state.apply("remote", 1, scope, "remote", Catalog::Record{19, bytes("remote"), Clock::Time(2s)}, State::Source::Form::Record));
    CHECK(state.versions(scope, keys).value() == std::vector<std::uint64_t>({7, 19, 0}));

    // After all bodies expire, SDK initialization still reads highest known versions from local and remote sources.
    now = 3s;
    state.tick();
    CHECK(state.capture(scope)->size() == 0);
    CHECK(state.versions(scope, keys).value() == std::vector<std::uint64_t>({7, 19, 0}));
    const std::array<std::string_view, 2> duplicates{"local", "local"}; // Duplicate keys are invalid bounded queries.
    CHECK(state.versions(scope, duplicates).error() == State::Error::Input);
    CHECK(state.versions(scope, {}).error() == State::Error::Input);
}

/// Content version, source sequence, and downstream cursor differ: Renew advances source only; local expiration advances downstream only.
void lifecycle() {

    auto now = 1000ms;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope left{"route", "left"};
    const Scope right{"route", "right"};
    const auto value = bytes("body");
    CHECK(state.publish(left, "key", value, 10, 1000));
    CHECK(state.publish(right, "key", bytes(""), 2, 1000));
    const auto frozen = state.capture(left);
    CHECK(frozen && frozen->version() == 1 && state.source().position() == 2);
    now = 1200ms;
    CHECK(state.renew(left, "key", 10, 2000));
    CHECK(state.source().position() == 3 && state.capture(left)->version() == 1);
    CHECK(state.publish(left, "key", bytes("body"), 10, 1000));
    CHECK(state.source().position() == 4 && state.capture(left)->version() == 1);
    const auto conflict = state.publish(left, "key", bytes("different"), 10, 1000);
    const auto obsolete = state.publish(left, "key", value, 9, 1000);
    CHECK(!conflict && conflict.error() == State::Error::Conflict);
    CHECK(!obsolete && obsolete.error() == State::Error::Version);
    CHECK(state.source().position() == 4);

    now = 2000ms;
    state.tick();
    CHECK(state.source().position() == 4 && state.source().size() == 2);
    CHECK(state.capture(right)->size() == 0 && state.capture(right)->version() == 2);
    CHECK(state.capture(left)->size() == 1);
    const auto missing = state.renew(right, "key", 2, 1000);
    CHECK(!missing && missing.error() == State::Error::Ended);
    const auto lower = state.publish(right, "key", value, 1, 1000);
    CHECK(!lower && lower.error() == State::Error::Version);
    CHECK(state.publish(right, "key", bytes(""), 2, 1000)); // Full publication may rebuild the same version; a watermark alone cannot renew.
    CHECK(state.source().position() == 5 && state.capture(right)->version() == 3);
    CHECK(state.publish(left, "key", value, 100, 1000)); // Higher skipped versions remain visible changes even with equal bodies.
    CHECK(state.capture(left)->version() == 2 && state.find(left, "key")->record->version == 100);
    frozen->each([&](const std::string& key, const State::Content& record) { CHECK(key == "key" && record.version == 10 && record.value == value); });
    const auto events = state.events(0);
    CHECK(events && events->size() == 6 && events->at(2).form == State::Source::Form::Renew);

    now += 1h;
    state.tick();
    CHECK(state.source().position() == 6 && state.source().size() == 2);
    state.source().each([](const Scope&, const std::string&, const Catalog::Record& record) { CHECK(record.version > 0 && !record.value && !record.deadline); });
    CHECK(state.capture(left)->size() == 0 && state.capture(right)->size() == 0);
}

/// Final sampling cannot revive an expired body; an established local clock remains usable without current Pulsar synchronization.
void boundary() {

    auto now = 1s;
    auto jump = 0s; // Jump after the first sample so preparation and final commit observe distinct times.
    State state([&] { const auto reading = Clock::Reading{.time = Clock::Time(now), .ready = true, .synchronized = false}; now += std::exchange(jump, 0s); return std::optional(reading); }, {});
    const Scope scope{"time", "boundary"};
    const auto value = bytes("v");
    jump = 2s;
    CHECK(state.publish(scope, "k", value, 1, 1000));
    state.source().each([](const Scope&, const std::string&, const Catalog::Record& record) { CHECK(record.deadline == Clock::Time(4s)); });
    jump = 2s;
    const auto rejected = state.renew(scope, "k", 1, 1000);
    CHECK(!rejected && rejected.error() == State::Error::Ended);
    state.tick();
    CHECK(state.source().position() == 1 && state.capture(scope)->size() == 0);
    CHECK(state.publish(scope, "k", value, 1, 1000));
    CHECK(state.source().position() == 2 && state.capture(scope)->version() == 3);
}

/// Shared reads preserve input/clock/cursor errors; sampler exceptions release locks and consume no empty-Scope quota.
void reads() {

    std::chrono::nanoseconds now = 1s; // Rejected readings cannot contaminate later monotonic checks.
    bool available = true;
    bool ready{};
    bool fail{};
    State::Limits limits; // One-Scope limit exposes accidental directory creation on error paths.
    limits.scopes = 1;
    State state([&]() -> std::optional<Clock::Reading> {
        if (std::exchange(fail, false)) {
            throw std::bad_alloc{};
        }
        if (!available) {
            return std::nullopt;
        }
        return Clock::Reading{.time = Clock::Time(now), .ready = ready};
    },
                limits);
    const Scope pending{"pending", "main"}, active{"active", "main"};
    CHECK(state.capture({}) == std::unexpected(State::Error::Input));
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    CHECK(state.find(pending, "key") == std::unexpected(State::Error::Clock));
    CHECK(state.changes(pending, 0) == std::unexpected(State::Error::Clock));
    CHECK(state.events(0) && state.events(0)->empty()); // Exporting an existing empty source needs no clock and performs no implicit cleanup.
    CHECK(state.deliver(0, 8, 4096));

    ready = fail = true;
    bool caught{};
    try {
        static_cast<void>(state.capture(pending));
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    CHECK(caught);
    for (unsigned index = 0; index < 4; ++index) {
        const Scope unknown{"unknown", std::to_string(index)}; // Read-only absent Scopes cannot consume quota needed by actual business writes.
        const auto view = state.capture(unknown);
        const auto point = state.find(unknown, "key");
        const auto replay = state.changes(unknown, 0);
        CHECK(view && view->version() == 0 && view->size() == 0 && view->bytes() == 0);
        CHECK(point && point->version == 0 && !point->record && !point->name);
        CHECK(replay && replay->empty());
        CHECK(state.changes(unknown, 1) == std::unexpected(State::Error::Input));
    }

    // Regressing readings cannot lower the confirmed floor; unready future readings cannot raise it.
    now = 500ms;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    now = 750ms;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    now = 10s;
    ready = false;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    ready = true;
    now = 1s;
    available = false;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    available = true;

    const auto empty = state.capture(active); // An absent-Scope frozen root stays empty after the first later write.
    CHECK(empty && state.publish(active, "key", bytes("body"), 1, 1000));
    CHECK(empty->page(0, 1, [](const auto&, const auto&) { CHECK(false); return true; }) == 0);
    CHECK(state.capture(active)->size() == 1 && state.capture(active)->version() == 1);
    CHECK(state.capture(pending)->version() == 0 && !state.find(pending, "key")->record && state.changes(pending, 0)->empty());
    CHECK(state.publish(pending, "key", bytes("body"), 1, 1000) == std::unexpected(State::Error::Capacity));
    CHECK(state.changes(active, 2) == std::unexpected(State::Error::Input)); // Future read cursors must not map to write-version exhaustion.
    CHECK(state.events(2) == std::unexpected(State::Error::Input));
    CHECK(state.deliver(2, 8, 4096) == std::unexpected(State::Error::Input));
}

/// Expiration releases final body ownership outside domain; destructor reentry checks the actual lock boundary.
void reclaim() {

    auto now = 1s;               // Fixed TTL from one to two seconds, without sleeps.
    bool released{}, unlocked{}; // Destruction/reentry flags outlive State.
    State::Limits limits;        // Disable both histories so retained payloads cannot hide reclamation timing.
    limits.history = limits.source.history = 0;
    const auto state = std::make_shared<State>([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope scope{"expiry", "reclaim"};
    Catalog::Value value(new Catalog::Buffer(16), [owner = std::weak_ptr<State>(state), &released, &unlocked](const Catalog::Buffer* payload) noexcept {
        released = true;
        try {
            const auto live = owner.lock(); // Failure cleanup cannot access already destroyed State members.
            unlocked = live && live->received("absent") == std::unexpected(State::Error::Input);
        } catch (...) {
            unlocked = false; // Destructor catches exceptions; outer assertions report contract failure.
        }
        delete payload;
    });
    CHECK(state->publish(scope, "key", value, 1, 1000));
    value.reset(); // Only production State retains the body, without fixture-owned final references.
    CHECK(!released);

    now = 2s;
    const auto view = state->capture(scope); // Shared read triggers TTL deletion and completes off-lock reclamation before return.
    CHECK(view && view->size() == 0 && released && unlocked);
}

/// Batch history pruning releases final old payload ownership outside domain too.
void batchReclaim() {

    bool released{}, unlocked{}; // Destructor reentry acquires domain to verify the actual history release boundary.
    State::Limits limits;
    limits.history = 0; // Disable projection history so only source history retains the final old reference.
    limits.source.history = 2;
    const auto state = std::make_shared<State>([] { return std::optional(Clock::Reading{.time = Clock::Time(1s), .ready = true}); }, limits);
    const Scope scope{"batch", "reclaim"};
    Catalog::Value previous(new Catalog::Buffer(16), [owner = std::weak_ptr<State>(state), &released, &unlocked](const Catalog::Buffer* payload) noexcept {
        released = true;
        try {
            const auto live = owner.lock();
            unlocked = live && live->received("absent") == std::unexpected(State::Error::Input);
        } catch (...) {
            unlocked = false;
        }
        delete payload;
    });
    CHECK(state->publish(scope, "a", previous, 1, 1000));
    CHECK(state->publish(scope, "a", bytes("new"), 2, 1000));
    previous.reset();
    CHECK(!released);

    const std::vector<State::Entry> entries{{"a", bytes("a")}, {"b", bytes("b")}};
    CHECK(state->publish(scope, entries, 3, 1000));
    CHECK(released && unlocked && state->events(2)->size() == 2);
}

/// Failed preparation consumes no Scope quota; expired watermarks remain bounded by native capacity despite repeated short leases.
void capacity() {

    auto now = 1s;
    State::Limits limits;
    limits.scopes = 1;
    limits.source.records = 1;
    limits.projection.bytes = 700;
    limits.history = 0;
    limits.source.history = 0;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope rejected{"rejected", "scope"};
    const Scope accepted{"accepted", "scope"};
    const auto large = std::make_shared<const Catalog::Buffer>(1024, 1);
    CHECK(!state.publish(rejected, "a", large, 1, 1000));
    CHECK(state.source().position() == 0 && state.source().size() == 0);
    CHECK(state.publish(accepted, "a", bytes("small"), 1, 1000));
    CHECK(state.changes(accepted, 0).error() == State::Error::History && state.events(0).error() == State::Error::History);
    now = 2s;
    state.tick();
    CHECK(state.source().size() == 1 && state.capture(accepted)->size() == 0);
    const auto full = state.publish(accepted, "b", bytes("small"), 1, 1000);
    CHECK(!full && full.error() == State::Error::Capacity);
    CHECK(state.source().position() == 1 && state.capture(accepted)->version() == 2);
    CHECK(state.publish(accepted, "a", bytes("new"), 2, 1000));
}

/// Batch commit/renew/failure/history use complete boundaries; concurrent snapshots cannot mix versions.
void batches() {

    auto now = 1s; // Fixed time isolates batch publication from expiration.
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"batch", "scope"};
    const std::vector<State::Entry> entries{{"a", bytes("a")}, {"b", bytes("b")}};
    CHECK(state.publish(scope, entries, 1, 1000));
    const auto frozen = state.capture(scope);
    const auto source = state.source(); // Freeze source and public roots for the complete batch.
    CHECK(frozen->size() == 2 && frozen->version() == 2 && source.position() == 2);
    std::atomic_bool valid{true};
    std::latch observed{1}; // Require a completed read before writes so lack of reader scheduling cannot give an empty pass.
    std::jthread reader([&](std::stop_token stop) {
        bool first = true;
        while (!stop.stop_requested()) {
            const auto view = state.capture(scope);
            std::optional<std::uint64_t> version; // Every record in the same captured view must have the same application version.
            view->each([&](const auto&, const auto& row) { if (version && *version != row.version){ valid.store(false);
} version = row.version; });
            if (view->size() != 2) {
                valid.store(false);
            }
            if (first) {
                first = false;
                observed.count_down();
            }
        }
    });
    observed.wait();
    for (std::uint64_t version = 2; version <= 32; ++version) {
        CHECK(state.publish(scope, entries, version, 1000));
    }
    reader.request_stop();
    reader.join();
    CHECK(valid.load());
    frozen->each([](const auto&, const auto& row) { CHECK(row.version == 1); });
    CHECK(state.changes(scope, 1).error() == State::Error::History); // Half-batch cursors are not installed baselines.
    CHECK(state.changes(scope, 62)->size() == 2);
    const std::vector<State::Entry> conflict{{"new", bytes("ok")}, {"b", bytes("conflict")}};
    CHECK(state.publish(scope, conflict, 32, 1000).error() == State::Error::Conflict);
    CHECK(!state.find(scope, "new")->record && state.source().position() == 64);
    const std::vector<State::Entry> renewal{{"a", {}}, {"missing", {}}};
    CHECK(state.publish(scope, renewal, 32, 2000, true).error() == State::Error::Ended);
    CHECK(state.source().position() == 64);
    const std::vector<State::Entry> complete{{"a", {}}, {"b", {}}};
    CHECK(state.publish(scope, complete, 32, 2000, true));
    CHECK(state.source().position() == 66 && state.capture(scope)->version() == 64);
}

// Single-entry public commits preserve the existing edit's snapshots, replay, renewal and refusals.
void singles() {

    auto now = 1000ms;    // Both paths consume the same controlled business clock.
    State::Limits limits; // Exercise bounded history after it has reached steady occupancy.
    limits.source.history = limits.projection.history = 16;
    State regular([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    State single([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope scope{"single", "scope"};
    const auto value = bytes("value"); // Identical immutable payload ownership on both paths.
    const std::vector<State::Entry> entries{{"key", value}};
    CHECK(regular.publish(scope, "key", value, 1, 1000) && single.publish(scope, entries, 1, 1000));
    const auto frozen = single.capture(scope); // A held first-version snapshot must survive every later commit.
    for (std::uint64_t version = 2; version <= 24; ++version) {
        CHECK(regular.publish(scope, "key", value, version, 1000) && single.publish(scope, entries, version, 1000));
        CHECK(single.source().position() == regular.source().position() && single.source().size() == regular.source().size());
        CHECK(single.capture(scope)->version() == regular.capture(scope)->version());
        CHECK(single.find(scope, "key")->record->version == version && single.find(scope, "key")->record->value == value);
    }
    frozen->each([](const auto&, const auto& row) { CHECK(row.version == 1); });
    const auto expected = regular.changes(scope, 8), actual = single.changes(scope, 8); // Same retained visible suffix.
    CHECK(expected && actual && expected->size() == 16 && actual->size() == expected->size());
    for (std::size_t index = 0; index < actual->size(); ++index) {
        CHECK((*actual)[index].version == (*expected)[index].version);
    }
    CHECK(single.changes(scope, 7).error() == regular.changes(scope, 7).error());
    CHECK(single.events(8)->size() == regular.events(8)->size() && single.events(8)->size() == 16);

    now = 1500ms;
    const std::vector<State::Entry> renewal{{"key", {}}}; // Renewal advances the source without a visible data event.
    CHECK(regular.renew(scope, "key", 24, 2000) && single.publish(scope, renewal, 24, 2000, true));
    CHECK(single.source().position() == 25 && regular.source().position() == 25);
    CHECK(single.capture(scope)->version() == 24 && regular.capture(scope)->version() == 24);
    CHECK(single.publish(scope, entries, 0, 1000).error() == State::Error::Input);
    CHECK(single.publish(scope, entries, 25, 999).error() == State::Error::Input);
    CHECK(single.publish(scope, entries, 25, 600001).error() == State::Error::Input);
    CHECK(single.publish(scope, entries, 24, 2000, true).error() == State::Error::Input);
    CHECK(single.publish(scope, renewal, 25, 1000).error() == State::Error::Input);
    const std::vector<State::Entry> invalid{{"", value}}, conflict{{"key", bytes("conflict")}};
    CHECK(single.publish(scope, invalid, 25, 1000).error() == State::Error::Input);
    CHECK(single.publish(scope, conflict, 24, 1000).error() == State::Error::Conflict);
    const std::vector<State::Entry> oversized{{"key", std::make_shared<const Catalog::Buffer>(1024 * 1024, 1)}};
    CHECK(single.publish(scope, oversized, 25, 1000).error() == State::Error::Capacity);
    CHECK(single.source().position() == 25 && single.capture(scope)->version() == 24);

    now = 4s;
    regular.tick();
    single.tick();
    CHECK(single.capture(scope)->size() == 0 && regular.capture(scope)->size() == 0);
    CHECK(single.capture(scope)->version() == regular.capture(scope)->version());
    CHECK(single.source().position() == regular.source().position());
    frozen->each([](const auto&, const auto& row) { CHECK(row.version == 1); });
}
} // namespace

/// Component state only; all time boundaries are controlled without network/database resources.
int main() {
    try {
        versions();
        exports<State>([](State& state, const Scope& scope) { CHECK(state.publish(scope, "key", bytes("value"), 1, 1000)); return std::string("key"); });
        batches();
        singles();
        lifecycle();
        boundary();
        reads();
        reclaim();
        batchReclaim();
        capacity();
        std::cout << "Catalog state tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
