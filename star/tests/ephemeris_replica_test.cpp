// Verify Ephemeris replication, ownership, and remote-expiry behavior.
#include "check.hpp"
#include "coverage.hpp"
#include "ephemeris_state.hpp"

#include <iostream>

namespace {
using namespace std::chrono_literals;
using astra::Clock;
using astra::Ephemeris;
using astra::Scope;
using State = Ephemeris::State;

/// Real shared immutable native Buffer, without serialization pretending to cross processes.
Ephemeris::Value bytes(std::string_view value) {
    return std::make_shared<const Ephemeris::Buffer>(value.begin(), value.end());
}

/// Reads complete records from the real local-source root, without borrowing replaceable pages.
Ephemeris::Record native(State& state, std::string_view uuid) {

    std::optional<Ephemeris::Record> result;
    state.source().each([&](const Scope&, const std::string& key, const Ephemeris::Record& value) {
        if (key == uuid) {
            result = value;
        }
    });
    CHECK(result);
    return *result;
}

/// Capture the full source, fill private candidates by Scope, then publish native state/projection.
void copy(State& sender, State& receiver, std::string_view id) {

    const auto source = sender.source();
    auto draft = receiver.prepare(id, source.position());
    CHECK(draft);
    source.each([&](const Scope& scope, const std::string& key, const Ephemeris::Record& value) { CHECK(draft->set(scope, key, value)); });
    CHECK(receiver.replace(id, std::move(*draft)));
}

/// Replica-local expiration never broadcasts. Full authority repair restores the same UUID without replay extending deadlines.
void lifetime() {

    auto leftTime = 1000ms, right_time = 1000ms;
    State left([&] { return std::optional(Clock::Reading{.time = Clock::Time(leftTime), .ready = true}); }, {});
    State right([&] { return std::optional(Clock::Reading{.time = Clock::Time(right_time), .ready = true}); }, {});
    const Scope scope{"service", "main"}, other{"service", "other"};
    CHECK(right.admit("star-a"));
    const auto first = left.create(scope, bytes("attr"), bytes("one"), 1000);
    const auto second = left.create(other, bytes("other-attr"), bytes("two"), 1000);
    const auto local = right.create(scope, bytes("local"), bytes("own"), 10000);
    CHECK(first && second && local);
    copy(left, right, "star-a");
    CHECK(right.received("star-a") == 2 && right.source().position() == 1);
    CHECK(right.capture(scope)->size() == 2 && right.capture(other)->size() == 1);
    CHECK(right.renew(scope, first->uuid, 1).error() == State::Error::Ended); // Replicas gain no authoritative write permission.

    right_time = 2200ms;
    right.tick();
    CHECK(right.capture(scope)->size() == 1 && right.capture(other)->size() == 0);
    CHECK(right.received("star-a") == 2 && right.source().position() == 1);
    CHECK(right.events(0)->size() == 1);
    leftTime = 1500ms;
    CHECK(left.renew(scope, first->uuid, 1));
    const auto renewed = native(left, first->uuid);
    CHECK(renewed.deadline == Clock::Time(2500ms));
    CHECK(right.apply("star-a", 3, scope, first->uuid, renewed, State::Source::Form::Renew).error() == State::Error::Ended);
    CHECK(right.received("star-a") == 2);
    CHECK(right.apply("star-a", 3, scope, first->uuid, renewed, State::Source::Form::Record));
    CHECK(right.find(scope, first->uuid)->record && right.received("star-a") == 3);
    auto replayed = renewed;
    replayed.deadline = Clock::Time(100s);
    CHECK(right.apply("star-a", 3, scope, first->uuid, replayed, State::Source::Form::Record));
    right_time = 2600ms;
    right.tick();
    CHECK(!right.find(scope, first->uuid)->record); // Same-position replay cannot adopt a forged later deadline.
    CHECK(right.find(scope, local->uuid)->record && right.source().position() == 1);
}

/// Replay old creation/authoritative deletion in order without exposing an already expired registration between them.
void expiry() {

    auto now = 1s; // Controlled business time, independent of real clocks/history-retention waits.
    State sender([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    State receiver([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"replay", "expired"};
    CHECK(receiver.admit("source"));
    const auto registration = sender.create(scope, bytes("attr"), bytes("data"), 1000);
    CHECK(registration);

    now = 2s; // Public history reads expire first without requiring caller tick.
    const auto changes = sender.changes(scope, 1);
    CHECK(changes && changes->size() == 1 && !changes->front().record);
    const auto delivery = sender.deliver(0, 8, 4096); // Authoritative expiration appends source erase while creation remains in contiguous history.
    CHECK(delivery && !delivery->baseline && delivery->events.size() == 2);
    CHECK(delivery->events.front().record && delivery->events.front().record->deadline == Clock::Time(2s));
    CHECK(!delivery->events.back().record && delivery->events.back().form == State::Source::Form::Erase);
    for (const auto& event : delivery->events) { // Check projection after every fact so final emptiness cannot hide transient revival.
        CHECK(receiver.apply("source", event.position, *event.name->scope, event.name->key, event.record, event.form));
        const auto visible = receiver.find(scope, registration->uuid); // Evaluate original deadline without granting TTL from receipt time.
        CHECK(visible && !visible->record && receiver.received("source") == event.position);
    }
    CHECK(receiver.source().position() == 0);
}

/// Check continuity, fixed Attr/TTL, independent orders, and identity collisions; rejection preserves installed position.
void ordering() {

    auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"service", "main"};
    const auto uuid = Ephemeris::uuid();
    Ephemeris::Record first{bytes("attr"), bytes("first"), Clock::Time(10s), 0, 0, 1000};
    CHECK(state.admit("a") && state.admit("b"));
    CHECK(!state.apply("a", 2, scope, uuid, first, State::Source::Form::Record));
    CHECK(state.received("a") == 0);
    CHECK(state.apply("a", 1, scope, uuid, first, State::Source::Form::Record));
    CHECK(state.apply("b", 1, scope, uuid, first, State::Source::Form::Record).error() == State::Error::Conflict);
    CHECK(state.received("b") == 0);
    auto bad = first;
    bad.attr = bytes("changed");
    CHECK(!state.apply("a", 2, scope, uuid, bad, State::Source::Form::Record));
    bad = first;
    bad.data = bytes("next");
    bad.update = 7;
    bad.deadline = Clock::Time(20s);
    CHECK(state.apply("a", 2, scope, uuid, bad, State::Source::Form::Data));
    const auto content = state.capture(scope);
    bad.renewal = 10;
    bad.deadline = Clock::Time(25s);
    CHECK(state.apply("a", 3, scope, uuid, bad, State::Source::Form::Renew));
    CHECK(state.capture(scope)->version() == content->version()); // Deadline-only updates repeat no bodies.
    auto invalid = bad;                                           // Full facts and targeted repair cannot change deadlines while bypassing renewal order.
    invalid.deadline = Clock::Time(30s);
    CHECK(!state.apply("a", 4, scope, uuid, invalid, State::Source::Form::Record));
    CHECK(!state.repair("a", 8, scope, uuid, invalid));
    auto baseline = state.prepare("a", 8);
    CHECK(baseline && baseline->set(scope, uuid, invalid));
    CHECK(!state.replace("a", std::move(*baseline)));
    invalid.renewal = 11;
    invalid.deadline = Clock::Time(15s);
    CHECK(!state.apply("a", 4, scope, uuid, invalid, State::Source::Form::Record));
    CHECK(state.received("a") == 3 && state.capture(scope)->version() == content->version());
    CHECK(state.apply("a", 4, scope, uuid, {}, State::Source::Form::Erase));
    CHECK(state.received("a") == 4 && !state.find(scope, uuid)->record);
    CHECK(state.source().position() == 0 && state.source().size() == 0);
    CHECK(state.events(0)->empty());
}

/// Projection preparation failure must preserve atomic source/Scope publication, not restore only native state after partial visibility changes.
void atomic() {

    auto now = 1s;
    State::Limits limits;
    limits.projection.records = 1;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope scope{"service", "main"};
    const auto original = Ephemeris::uuid(), other = Ephemeris::uuid();
    const Ephemeris::Record value{bytes("attr"), bytes("value"), Clock::Time(10s), 0, 0, 1000};
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, scope, original, value, State::Source::Form::Record));
    const auto frozen = state.capture(scope);
    auto draft = state.prepare("a", 5);
    CHECK(draft && draft->set(scope, original, value) && draft->set(scope, other, value));
    CHECK(!state.replace("a", std::move(*draft)));
    CHECK(state.received("a") == 1 && state.capture(scope)->version() == frozen->version());
    CHECK(state.find(scope, original)->record && !state.find(scope, other)->record);
    draft = state.prepare("a", 5); // A later atomic delete/insert proves failure leaked no Scope, ownership, or capacity.
    CHECK(draft && draft->set(scope, other, value));
    CHECK(state.replace("a", std::move(*draft)));
    CHECK(state.received("a") == 5 && !state.find(scope, original)->record && state.find(scope, other)->record);
    frozen->each([&](const std::string& key, const auto&) { CHECK(key == original); });
    CHECK(!state.prepare("a", 4));
    auto empty = state.prepare("a", 6);
    CHECK(empty && state.replace("a", std::move(*empty)));
    CHECK(state.received("a") == 6 && state.capture(scope)->size() == 0);
}

/// Equal bytes at distinct addresses remain invisible; suffix differences and equal-order conflicts do not.
void sharing() {

    // Keep the first eight bytes equal even when the last byte changes.
    const auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"content", "selection"};
    const auto uuid = Ephemeris::uuid();
    const std::string text(65536, 'a');
    auto changed = text;
    changed.back() = 'b';
    const Ephemeris::Record original{bytes(text), bytes(text), Clock::Time(10s), 0, 0, 1000, 1};
    CHECK(state.admit("a") && state.admit("b") && state.admit("c"));
    CHECK(state.apply("a", 1, scope, uuid, original, State::Source::Form::Record));
    const auto frozen = state.capture(scope);
    CHECK(frozen && frozen->version() == 1);

    // Remote records retain their own immutable buffers, unlike local equal-body canonicalization.
    auto equal = original;
    equal.attr = bytes(text);
    equal.data = bytes(text);
    equal.update = 1;
    CHECK(equal.attr != original.attr && equal.data != original.data);
    CHECK(state.apply("a", 2, scope, uuid, equal, State::Source::Form::Record));
    CHECK(state.capture(scope)->version() == 1);
    auto latest = equal;
    latest.data = bytes(changed);
    latest.update = 2;
    CHECK(state.apply("a", 3, scope, uuid, latest, State::Source::Form::Data));
    CHECK(state.capture(scope)->version() == 2 && *state.find(scope, uuid)->record->data == *latest.data);
    latest.renewal = 1;
    latest.deadline = Clock::Time(11s);
    CHECK(state.apply("a", 4, scope, uuid, latest, State::Source::Form::Renew));
    CHECK(state.capture(scope)->version() == 2);

    // A second source with equal bytes is legal; a new source cannot alter Attr or equal-order Data.
    auto overlap = latest;
    overlap.attr = bytes(text);
    overlap.data = bytes(changed);
    overlap.generation = 2;
    CHECK(state.apply("b", 1, scope, uuid, overlap, State::Source::Form::Record));
    CHECK(state.capture(scope)->version() == 2);
    auto conflict = overlap;
    conflict.attr = bytes(changed);
    CHECK(state.apply("c", 1, scope, uuid, conflict, State::Source::Form::Record) == std::unexpected(State::Error::Conflict));
    conflict = overlap;
    conflict.data = bytes(text);
    CHECK(state.apply("c", 1, scope, uuid, conflict, State::Source::Form::Record) == std::unexpected(State::Error::Conflict));
    CHECK(state.received("c") == 0 && state.capture(scope)->version() == 2);

    CHECK(state.apply("b", 2, scope, uuid, {}, State::Source::Form::Erase));
    CHECK(state.capture(scope)->version() == 2 && *state.find(scope, uuid)->record->data == *latest.data);
    CHECK(state.apply("a", 5, scope, uuid, {}, State::Source::Form::Erase));
    CHECK(state.capture(scope)->version() == 3 && !state.find(scope, uuid)->record);
    frozen->each([&](const std::string& key, const State::Content& record) { CHECK(key == uuid && record.attr == original.attr && record.data == original.data); });
}

/// Failed source updates and moved baseline preparations must not leave hidden candidate changes.
void rollback() {

    // A later source join observes candidate state independently of the unchanged public root.
    for (const bool baseline : {false, true}) {
        const auto now = 1s;
        State::Limits limits;
        limits.projection.records = 1;
        limits.projection.bytes = 700;
        State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
        const Scope scope{"rollback", "selection"};
        const auto uuid = Ephemeris::uuid(), other = Ephemeris::uuid();
        const Ephemeris::Record original{bytes("attr"), bytes("old"), Clock::Time(10s), 0, 0, 1000, 1};
        CHECK(state.admit("a") && state.admit("b"));
        CHECK(state.apply("a", 1, scope, uuid, original, State::Source::Form::Record));
        const auto frozen = state.capture(scope);
        CHECK(frozen && frozen->version() == 1);

        // A delta exceeds bytes; a baseline fits each body but exceeds the record count.
        auto candidate = original;
        candidate.data = bytes(baseline ? std::string("uncommitted") : std::string(1024, 'x'));
        candidate.update = 1;
        if (baseline) {
            auto draft = state.prepare("a", 2);
            CHECK(draft && draft->set(scope, uuid, candidate) && draft->set(scope, other, original));
            CHECK(state.replace("a", std::move(*draft)) == std::unexpected(State::Error::Capacity));
        } else {
            CHECK(state.apply("a", 2, scope, uuid, candidate, State::Source::Form::Data) == std::unexpected(State::Error::Capacity));
        }
        CHECK(state.received("a") == 1 && state.capture(scope)->version() == 1);
        CHECK(state.replica("a", scope, uuid)->value().data == original.data);
        CHECK(!state.find(scope, other)->record);

        auto overlap = original;
        overlap.attr = bytes("attr");
        overlap.data = bytes("old");
        overlap.generation = 2;
        CHECK(state.apply("b", 1, scope, uuid, overlap, State::Source::Form::Record));
        CHECK(state.capture(scope)->version() == 1 && *state.find(scope, uuid)->record->data == *original.data);
        CHECK(state.apply("b", 2, scope, uuid, {}, State::Source::Form::Erase));
        CHECK(state.capture(scope)->version() == 1 && state.find(scope, uuid)->record->data == original.data);

        // A healthy retry can commit the same next source position and Data order.
        candidate.data = bytes("committed");
        CHECK(state.apply("a", 2, scope, uuid, candidate, State::Source::Form::Data));
        CHECK(state.received("a") == 2 && state.capture(scope)->version() == 2);
        CHECK(state.find(scope, uuid)->record->data == candidate.data && state.source().position() == 0);
        frozen->each([&](const std::string& key, const State::Content& record) { CHECK(key == uuid && record.data == original.data); });
    }
}

/// Targeted UUID repair still processes other intermediate facts; expiration cannot discard coverage evidence.
void repair() {

    auto now = 1000ms;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope firstScope{"service", "one"}, secondScope{"service", "two"};
    const auto first = Ephemeris::uuid(), second = Ephemeris::uuid();
    Ephemeris::Record original{bytes("attr"), bytes("old"), Clock::Time(2s), 0, 0, 1000};
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, firstScope, first, original, State::Source::Form::Record));
    auto repaired = original;
    repaired.data = bytes("future");
    repaired.update = 3;
    repaired.renewal = 3;
    repaired.deadline = Clock::Time(3s);
    CHECK(state.repair("a", 5, firstScope, first, repaired));
    CHECK(state.received("a") == 1); // R=5 is not a source-wide contiguous position.
    CHECK(!state.prepare("a", 4));   // A lower baseline cannot revoke stronger target coverage.
    CHECK(state.replica("a", firstScope, first)->value().data == repaired.data);
    CHECK(state.apply("a", 2, secondScope, second, original, State::Source::Form::Record));
    now = 3500ms;
    state.tick(); // Coverage survives both targets' local expiration.
    CHECK(!state.find(firstScope, first)->record);
    original.update = 1;
    original.data = bytes("stale");
    CHECK(state.apply("a", 3, firstScope, first, original, State::Source::Form::Data));
    CHECK(state.apply("a", 4, firstScope, first, {}, State::Source::Form::Erase));
    auto current = original;
    current.deadline = Clock::Time(5s);
    CHECK(state.apply("a", 5, secondScope, second, current, State::Source::Form::Record));
    CHECK(state.received("a") == 5 && state.find(secondScope, second)->record);
    CHECK(!state.find(firstScope, first)->record);
    CHECK(state.prepare("a", 5)); // Once the contiguous prefix covers R, reclaim metadata without preventing valid same-position baseline repair.
    CHECK(state.source().position() == 0);
}

/// Trusted replacement freezes new input without deleting live old registrations; original expiration later releases empty-source capacity.
void replacement() {

    auto now = 1000ms;
    State::Limits limits;
    limits.replicas = 1;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope scope{"service", "main"};
    const auto uuid = Ephemeris::uuid();
    const Ephemeris::Record value{bytes("attr"), bytes("value"), Clock::Time(2s), 0, 0, 1000};
    CHECK(state.admit("old"));
    CHECK(state.apply("old", 1, scope, uuid, value, State::Source::Form::Record));
    auto delayed = state.prepare("old", 2);
    CHECK(delayed && delayed->set(scope, uuid, value));
    state.retire("old");
    CHECK(state.find(scope, uuid)->record && !state.admit("old"));
    CHECK(!state.replace("old", std::move(*delayed)));
    CHECK(!state.apply("old", 2, scope, uuid, {}, State::Source::Form::Erase));
    CHECK(!state.admit("new")); // Live native data still consumes source budget after stream cancellation.
    now = 2100ms;
    state.tick();
    CHECK(!state.find(scope, uuid)->record && !state.received("old"));
    CHECK(state.admit("new"));
    CHECK(state.source().position() == 0);
}

/// Installed Scope coverage survives cancellation/TTL cleanup; full-source confirmation waits for remaining Scope replay.
void interrupted() {

    auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope one{"a", "main"}, two{"b", "main"};
    const auto first = Ephemeris::uuid(), second = Ephemeris::uuid(), absent = Ephemeris::uuid();
    const Ephemeris::Record old{bytes("attr"), bytes("old"), Clock::Time(2s), 0, 0, 1000};
    auto newer = old; // Same UUID keeps Attr/TTL fixed while both orders/deadline advance.
    newer.data = bytes("new");
    newer.update = newer.renewal = 1;
    newer.deadline = Clock::Time(4s);
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, one, first, old, State::Source::Form::Record));
    CHECK(state.apply("a", 2, two, second, old, State::Source::Form::Record));
    {
        auto draft = state.prepare("a", 5);
        CHECK(draft && draft->set(one, first, newer) && draft->set(two, second, newer));
        auto task = state.restore("a", std::move(*draft));
        CHECK(task && task->step() == false);
        CHECK(state.received("a") == 2 && *state.find(one, first)->record->data == *newer.data && *state.find(two, second)->record->data == *old.data);
        CHECK(state.create(two, bytes("own"), bytes("data"), 1000));
    }
    now = 5s;
    state.tick();
    CHECK(state.covered("a", 3, one, absent) == true);
    CHECK(state.apply("a", 4, one, first, {}, State::Source::Form::Erase));
    newer.deadline = Clock::Time(10s);
    CHECK(state.apply("a", 5, two, second, newer, State::Source::Form::Record));
    CHECK(state.received("a") == 5 && !state.find(one, first)->record && !state.find(one, absent)->record);
    CHECK(state.find(two, second)->record);
}

/// Same-logical-ID recovery chooses newer Data, exposes one record across sources, and rejects stale generations/forged capabilities.
void recovery() {

    auto a = 1000ms, b = 1500ms, c = 1500ms;
    State first([&] { return std::optional(Clock::Reading{.time = Clock::Time(a), .ready = true}); }, {});
    State second([&] { return std::optional(Clock::Reading{.time = Clock::Time(b), .ready = true}); }, {});
    State observer([&] { return std::optional(Clock::Reading{.time = Clock::Time(c), .ready = true}); }, {});
    const Scope scope{"stable", "identity"};
    const auto attr = bytes("fixed");
    const auto capability = Ephemeris::capability();
    const auto id = Ephemeris::identity(scope, attr, 1000, capability);
    CHECK(first.create(scope, attr, bytes("confirmed"), 1000, id, 1, 0, capability));
    a = 1200ms;
    CHECK(first.update(scope, id, bytes("unknown"), 1, 1, capability)); // Simulates a lost receipt.
    CHECK(second.admit("a") && observer.admit("a") && observer.admit("b"));
    copy(first, second, "a");
    const auto restored = second.create(scope, attr, bytes("confirmed"), 1000, id, 2, 0, capability);
    CHECK(restored && restored->uuid == id && restored->order == 1 && *restored->data == *bytes("unknown"));
    CHECK(native(second, id).generation == 2 && native(second, id).deadline == Clock::Time(2500ms));
    b = 1600ms;
    CHECK(second.create(scope, attr, bytes("confirmed"), 1000, id, 2, 0, capability));
    CHECK(native(second, id).deadline == Clock::Time(2500ms)); // Repeated registration generation confirms without renewing TTL.
    CHECK(!second.update(scope, id, bytes("old"), 2, 1, capability));
    CHECK(!second.renew(scope, id, 1, 1, capability));
    CHECK(!second.remove(scope, id, 1, capability));
    CHECK(!second.create(scope, attr, bytes("forged"), 1000, id, 3, 2, Ephemeris::capability()));
    copy(first, observer, "a");
    copy(second, observer, "b");
    CHECK(observer.capture(scope)->size() == 1 && *observer.find(scope, id)->record->data == *bytes("unknown"));
    CHECK(first.update(scope, id, bytes("latest"), 2, 1, capability));
    copy(first, observer, "a");
    CHECK(observer.capture(scope)->size() == 1 && *observer.find(scope, id)->record->data == *bytes("latest"));
    c = 2300ms;
    observer.tick();
    CHECK(observer.capture(scope)->size() == 1 && *observer.find(scope, id)->record->data == *bytes("unknown")); // After the higher-version source expires, a valid lower-version contribution remains visible.
    c = 2600ms;
    observer.tick();
    CHECK(observer.capture(scope)->size() == 0);
    b = 2600ms;
    CHECK(second.create(scope, attr, bytes("unknown"), 1000, id, 3, 1, capability)); // Recovery after expiration preserves logical ID without fabricating a Data order.
    CHECK(native(second, id).update == 1 && native(second, id).generation == 3);
}

/// A valid lower-order source must be visible after a competing deadline, before the next timer tick.
void precision() {

    // Sources issue real capability-bound records; the recovering source has not learned the lost update.
    for (const bool baseline : {false, true}) {
        auto a = 1005ms, b = 1100ms, c = 1000ms;
        State first([&] { return std::optional(Clock::Reading{.time = Clock::Time(a), .ready = true}); }, {});
        State second([&] { return std::optional(Clock::Reading{.time = Clock::Time(b), .ready = true}); }, {});
        State observer([&] { return std::optional(Clock::Reading{.time = Clock::Time(c), .ready = true}); }, {});
        const Scope scope{"subtick", "selection"};
        const auto attr = bytes("fixed"), confirmed = bytes("confirmed"), unknown = bytes("unknown");
        const auto capability = Ephemeris::capability();
        const auto id = Ephemeris::identity(scope, attr, 1000, capability);
        CHECK(first.create(scope, attr, confirmed, 1000, id, 1, 0, capability));
        CHECK(first.update(scope, id, unknown, 1, 1, capability));
        CHECK(second.create(scope, attr, confirmed, 1000, id, 2, 0, capability));
        CHECK(native(first, id).deadline == Clock::Time(2005ms) && native(second, id).deadline == Clock::Time(2100ms));
        CHECK(observer.admit("a") && observer.admit("b"));
        copy(first, observer, "a");
        const auto frozen = observer.capture(scope);
        CHECK(frozen && frozen->version() == 1 && observer.find(scope, id)->record->data == unknown);

        // The 10 ms timer still holds the expired source through 2006 ms; selection uses the exact deadline.
        c = 2006ms;
        CHECK(observer.replica("a", scope, id)->value().deadline == Clock::Time(2005ms));
        if (baseline) {
            copy(second, observer, "b");
        } else {
            CHECK(observer.apply("b", 1, scope, id, native(second, id), State::Source::Form::Record));
        }
        CHECK(observer.received("a") == 2 && observer.received("b") == 1);
        CHECK(observer.capture(scope)->version() == 2 && observer.find(scope, id)->record->data == confirmed);
        CHECK(observer.replica("a", scope, id)->value().deadline == Clock::Time(2005ms));
        frozen->each([&](const std::string& key, const State::Content& record) { CHECK(key == id && record.attr == attr && record.data == unknown); });

        // Retiring the stale timer at the next whole tick cannot erase or republish the surviving source.
        c = 2010ms;
        observer.tick();
        CHECK(!observer.replica("a", scope, id)->has_value());
        CHECK(observer.capture(scope)->version() == 2 && observer.find(scope, id)->record->data == confirmed);
        CHECK(observer.source().position() == 0);
    }
}

} // namespace

/// Native multi-source cases complement separate real-network replication acceptance.
int main() {

    try {
        recovery();
        precision();
        lifetime();
        expiry();
        ordering();
        atomic();
        sharing();
        rollback();
        interrupted();
        coverage<Ephemeris>({bytes("attr"), bytes("old"), Clock::Time(4s), 0, 0, 1000}, {bytes("attr"), bytes("new"), Clock::Time(5s), 1, 1, 1000}, {Ephemeris::uuid(), Ephemeris::uuid(), Ephemeris::uuid()});
        capacity<Ephemeris>({bytes("attr"), bytes("data"), Clock::Time(10s), 0, 0, 1000});
        repair();
        replacement();
        std::cout << "Ephemeris replicas: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
