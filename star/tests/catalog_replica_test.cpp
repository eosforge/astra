// Verify Catalog source replication, coverage, and merged-view recovery.
#include "catalog_state.hpp"
#include "check.hpp"
#include "coverage.hpp"

#include <iostream>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Scope;
using State = Catalog::State;

/// Complete immutable body; empty text is present and cannot impersonate a watermark.
Catalog::Value bytes(std::string_view text) {
    return std::make_shared<const Catalog::Buffer>(text.begin(), text.end());
}

/// Synthetic facts carry fixed absolute deadlines; receivers never add TTL from receipt time.
Catalog::Record record(std::uint64_t version, std::string_view value = "body", Clock::Time deadline = Clock::Time(10s)) {
    return {version, bytes(value), deadline};
}

/// Transfer a real local-source root through Draft, not a merged public view.
void copy(State& sender, State& receiver, std::string_view id) {

    const auto source = sender.source();
    auto draft = receiver.prepare(id, source.position());
    CHECK(draft);
    source.each([&](const Scope& scope, const std::string& key, const Catalog::Record& value) { CHECK(draft->set(scope, key, value)); });
    CHECK(receiver.replace(id, std::move(*draft)));
}

/// Separate local source, merged watermarks, and public projection; remote deadlines cannot extend local Renew eligibility.
void sources() {

    auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"route", "main"};
    CHECK(state.admit("a") && state.admit("b"));
    CHECK(state.publish(scope, "key", bytes("body"), 2, 1000));
    CHECK(state.apply("a", 1, scope, "key", record(2), State::Source::Form::Record));
    CHECK(state.source().position() == 1 && state.capture(scope)->version() == 1);
    now = 3s;
    state.tick();
    CHECK(state.find(scope, "key")->record->version == 2);
    CHECK(state.renew(scope, "key", 2, 1000).error() == State::Error::Ended);
    state.source().each([](const Scope&, const std::string&, const Catalog::Record& value) { CHECK(value.version == 2 && !value.value); });
    CHECK(state.apply("b", 1, scope, "key", record(8, "new"), State::Source::Form::Record));
    CHECK(state.publish(scope, "key", bytes("body"), 2, 1000).error() == State::Error::Version);
    CHECK(state.apply("a", 2, scope, "key", record(3, "old"), State::Source::Form::Record));
    CHECK(state.find(scope, "key")->record->version == 8 && state.capture(scope)->version() == 2);
    CHECK(state.replica("a", scope, "key")->value().version == 3);
    CHECK(state.source().position() == 1); // Learned higher versions cannot rewrite local-source watermark/broadcast facts.

    now = 11s;
    state.tick();
    CHECK(!state.find(scope, "key")->record && state.capture(scope)->version() == 3);
    CHECK(state.publish(scope, "key", bytes("old"), 7, 1000).error() == State::Error::Version);
    CHECK(state.apply("a", 3, scope, "key", record(6, "older", Clock::Time(20s)), State::Source::Form::Record));
    CHECK(!state.find(scope, "key")->record);
    CHECK(state.apply("b", 2, scope, "key", record(8, "new", Clock::Time(20s)), State::Source::Form::Renew).error() == State::Error::Ended);
    CHECK(state.repair("b", 2, scope, "key", record(8, "new", Clock::Time(20s))));
    CHECK(state.received("b") == 1 && state.find(scope, "key")->record->version == 8);
    CHECK(state.apply("b", 2, scope, "key", record(8, "new", Clock::Time(20s)), State::Source::Form::Renew));
    CHECK(state.received("b") == 2 && state.source().position() == 1);
}

/// Retained source history may contain expired bodies; replay keeps original deadlines and restores only watermarks.
void expiry() {

    auto now = 1s; // Controlled business time is separate from monotonic history-retention age.
    State sender([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    State receiver([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"replay", "expired"};
    CHECK(receiver.admit("source") && sender.publish(scope, "key", bytes("body"), 1, 1000));

    now = 2s;                                      // Reading increments at exact TTL first expires locally, without requiring an explicit tick.
    const auto changes = sender.changes(scope, 1); // Downstream receives deletion despite the old creation remaining in source history.
    CHECK(changes && changes->size() == 1 && !changes->front().record);
    const auto delivery = sender.deliver(0, 8, 4096); // Catalog expiration creates no source event; original creation history remains readable.
    CHECK(delivery && !delivery->baseline && delivery->events.size() == 1);
    const auto& event = delivery->events.front();
    CHECK(event.record && event.record->value && event.record->deadline == Clock::Time(2s));
    CHECK(receiver.apply("source", event.position, *event.name->scope, event.name->key, *event.record, event.form));
    const auto known = receiver.replica("source", scope, "key"); // Late facts confirm position/raise the floor without retaining live bodies.
    CHECK(known && *known && (**known).version == 1 && !(**known).value && !(**known).deadline);
    const auto visible = receiver.find(scope, "key"); // Expired content must never reappear in public projection, even transiently.
    CHECK(visible && !visible->record && receiver.received("source") == 1 && receiver.source().position() == 0);
}

/// Watermarks/missing baseline entries do not broadcast Catalog expiration; higher floors exclude live lower versions.
void watermarks() {

    auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"route", "main"};
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, scope, "key", record(5), State::Source::Form::Record));
    const auto frozen = state.capture(scope);
    auto mark = state.prepare("a", 1);
    CHECK(mark && mark->set(scope, "key", {5, {}, {}}));
    CHECK(state.replace("a", std::move(*mark)));
    CHECK(state.find(scope, "key")->record && state.capture(scope)->version() == 1);
    auto empty = state.prepare("a", 1);
    CHECK(empty && state.replace("a", std::move(*empty)));
    CHECK(state.find(scope, "key")->record && !state.replica("a", scope, "key")->has_value());
    CHECK(state.apply("a", 2, scope, "key", {9, {}, {}}, State::Source::Form::Record));
    CHECK(!state.find(scope, "key")->record && state.capture(scope)->version() == 2);
    frozen->each([](const std::string& key, const State::Content& value) { CHECK(key == "key" && value.version == 5 && *value.value == *bytes("body")); });
    CHECK(state.publish(scope, "key", bytes("lower"), 8, 1000).error() == State::Error::Version);
    CHECK(state.repair("a", 3, scope, "key", {}));
    CHECK(state.publish(scope, "key", bytes("lower"), 8, 1000).error() == State::Error::Version); // Unknown source facts cannot zero the merged floor.
    CHECK(state.publish(scope, "key", bytes(""), 9, 1000));
    CHECK(state.find(scope, "key")->record->value->empty());
}

/// Repair R covers only its target and blocks old facts/deadlines through R even after local expiration.
void repair() {

    auto now = 1s;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope one{"one", "main"}, two{"two", "main"};
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, one, "key", record(1), State::Source::Form::Record));
    CHECK(state.repair("a", 5, one, "key", record(3, "new", Clock::Time(2s))));
    CHECK(state.received("a") == 1);
    now = 3s;
    state.tick();
    CHECK(!state.find(one, "key")->record);
    CHECK(state.apply("a", 2, two, "other", record(1), State::Source::Form::Record));
    CHECK(state.apply("a", 3, one, "key", record(2, "old", Clock::Time(100s)), State::Source::Form::Record));
    CHECK(state.apply("a", 4, one, "key", record(2, "old", Clock::Time(101s)), State::Source::Form::Renew));
    CHECK(!state.find(one, "key")->record && state.received("a") == 4);
    CHECK(state.prepare("a", 4).error() == State::Error::Version); // Full baseline cannot erase stronger targeted coverage at R=5.
    CHECK(state.apply("a", 5, two, "other", record(2, "other"), State::Source::Form::Record));
    CHECK(state.received("a") == 5 && state.find(two, "other")->record->version == 2);
    CHECK(state.apply("a", 6, one, "key", record(3, "new", Clock::Time(20s)), State::Source::Form::Record));
    CHECK(state.find(one, "key")->record->version == 3);
    CHECK(state.apply("a", 8, one, "key", record(4), State::Source::Form::Record).error() == State::Error::History);
}

/// Per-Scope atomic recovery preserves earlier successes after later capacity failure, without early source-wide confirmation.
void rollback() {

    auto now = 1s;
    State::Limits limits;
    limits.projection.records = 1;
    State source([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    State target([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope one{"one", "main"}, two{"two", "main"};
    CHECK(source.publish(one, "key", bytes("a"), 1, 1000));
    CHECK(source.publish(two, "key", bytes("b"), 1, 1000));
    CHECK(target.admit("source"));
    copy(source, target, "source");
    auto draft = target.prepare("source", 3);
    CHECK(draft && draft->set(one, "key", record(9)) && draft->set(two, "key", record(9)) && draft->set(two, "extra", record(1)));
    CHECK(target.replace("source", std::move(*draft)).error() == State::Error::Capacity);
    CHECK(target.received("source") == 2 && target.find(one, "key")->record->version == 9 && target.find(two, "key")->record->version == 1);
    CHECK(!target.find(two, "extra")->record);
    CHECK(target.publish(one, "key", bytes("local"), 2, 1000).error() == State::Error::Version);
    now = 3s;
    target.tick();
    CHECK(target.find(one, "key")->record && !target.find(two, "key")->record); // Installed Scopes use new deadlines; a failed Scope retains old expiration behavior.
}

/// Equal-version conflict rejects installation; retirement blocks old tasks and group reclamation preserves learned watermark floors.
void retired() {

    auto now = 1s;
    State::Limits limits;
    limits.replicas = 1;
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const Scope scope{"route", "main"};
    CHECK(state.admit("old"));
    CHECK(state.apply("old", 1, scope, "key", record(10, "v", Clock::Time(2s)), State::Source::Form::Record));
    CHECK(state.apply("old", 2, scope, "key", record(10, "bad"), State::Source::Form::Record).error() == State::Error::Conflict);
    CHECK(state.received("old") == 1);
    auto delayed = state.prepare("old", 2);
    CHECK(delayed && delayed->set(scope, "key", record(20)));
    state.retire("old");
    CHECK(state.replace("old", std::move(*delayed)).error() == State::Error::Version);
    CHECK(state.admit("next").error() == State::Error::Capacity);
    CHECK(state.find(scope, "key")->record->version == 10);
    now = 3s;
    state.tick();
    CHECK(state.admit("next"));
    CHECK(state.apply("next", 1, scope, "key", record(9), State::Source::Form::Record));
    CHECK(!state.find(scope, "key")->record);
    CHECK(state.publish(scope, "key", bytes("old"), 9, 1000).error() == State::Error::Version);
}

/// Interrupted recovery retains Scope coverage against stale missing-key increments; other Scopes/local writes proceed between steps.
void interrupted() {

    auto now = 1s; // Fixed epoch time removes sleep-dependent boundaries.
    State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope one{"a", "main"}, two{"b", "main"}; // Address order installs a before cancellation ahead of b.
    CHECK(state.admit("a"));
    CHECK(state.apply("a", 1, one, "key", record(1), State::Source::Form::Record));
    CHECK(state.apply("a", 2, two, "key", record(1), State::Source::Form::Record));
    {
        auto draft = state.prepare("a", 5);
        CHECK(draft && draft->set(one, "key", record(5)) && draft->set(two, "key", record(5)));
        auto task = state.restore("a", std::move(*draft));
        CHECK(task && task->step() == false);
        CHECK(state.received("a") == 2 && state.find(one, "key")->record->version == 5 && state.find(two, "key")->record->version == 1);
        CHECK(state.publish(two, "own", bytes("local"), 1, 1000));
    }
    CHECK(state.prepare("a", 4).error() == State::Error::Version);
    CHECK(state.apply("a", 3, one, "missing", record(2), State::Source::Form::Record));
    CHECK(!state.find(one, "missing")->record && state.received("a") == 3);
    CHECK(state.repair("a", 6, one, "key", record(6))); // Targeted repair may exceed Scope coverage; each evidence type is reclaimed independently.
    CHECK(state.apply("a", 4, one, "key", record(4), State::Source::Form::Record));
    CHECK(state.apply("a", 5, two, "key", record(5), State::Source::Form::Record));
    CHECK(state.apply("a", 6, one, "key", record(6), State::Source::Form::Record));
    CHECK(state.received("a") == 6 && state.find(one, "key")->record->version == 6);
    CHECK(state.source().position() == 1); // Receiver broadcasts only its own local writes.
}

} // namespace

int main() {

    try {
        sources();
        expiry();
        watermarks();
        repair();
        rollback();
        interrupted();
        coverage<Catalog>({1, bytes("old"), Clock::Time(4s)}, {2, bytes("new"), Clock::Time(5s)}, {"first", "second", "third"});
        capacity<Catalog>({1, bytes("data"), Clock::Time(10s)});
        retired();
        std::cout << "catalog replicas: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
