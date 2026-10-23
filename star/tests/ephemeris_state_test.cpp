// Verify Ephemeris native state, ownership, quotas, and scheduled expiration.
#include "check.hpp"
#include "ephemeris_state.hpp"
#include "exports.hpp"

#include <array>
#include <iostream>
#include <new>
#include <string>

namespace {
using namespace std::chrono_literals;
using astra::Clock;
using astra::Ephemeris;
using astra::Scope;
using State = Ephemeris::State;

/// Deterministic provider injected through real State construction, without wall-clock reads or sleeps.
struct Time {
    /// Nonnegative application time, initially one second.
    std::chrono::nanoseconds value = 1s;
    /// One-shot post-sample jump, initially zero, for expiration during preparation.
    std::chrono::nanoseconds jump{};
    /// False means local time unestablished, distinct from reference disconnection.
    bool ready = true;

    /// Return current reading, then apply jump to cross TTL between preparation and final sample.
    std::optional<Clock::Reading> read() {
        const auto reading = Clock::Reading{.time = Clock::Time(value), .ready = ready, .synchronized = false};
        value += std::exchange(jump, 0ns);
        return reading;
    }
};

/// Immutable test payload; empty bytes retain nonnull ownership.
Ephemeris::Value bytes(std::string_view text) {
    return std::make_shared<const Ephemeris::Buffer>(text.begin(), text.end());
}

/// Fixed notification table; noexcept collector neither allocates under business locks nor calls users.
struct Notice {
    /// Scope cursors in actual notification order.
    std::array<std::uint64_t, 32> versions{};
    /// Notification count, initially zero.
    std::size_t size{};
    /// Explicit overflow failure instead of out-of-bounds access.
    bool overflow{};

    static void receive(void* context, const Scope&, const State::Projection::Event& event) noexcept {
        auto& self = *static_cast<Notice*>(context);
        if (self.size == self.versions.size()) {
            self.overflow = true;
            return;
        }
        self.versions[self.size++] = event.version;
    }
};

/// Real composition: source positions span Scopes, visible cursors remain per Scope, and renewal creates no Attr/Data content event.
void lifecycle() {

    Time time;
    State state([&] { return time.read(); }, {});
    Notice notice;
    state.notify(Notice::receive, &notice);
    const Scope left{"service", "left"};
    const Scope right{"service", "right"};
    const auto attr = bytes("fixed");
    const auto initial = bytes("one");
    const auto first = state.create(left, attr, initial, 1000);
    const auto second = state.create(right, attr, bytes(""), 1000);
    CHECK(first && second && first->uuid != second->uuid && Ephemeris::valid(first->uuid));
    CHECK(state.source().position() == 2 && state.source().size() == 2);
    const auto frozen = state.capture(left);
    const auto foreign = state.capture(right);
    CHECK(frozen && foreign && frozen->version() == 1 && foreign->version() == 1);
    CHECK(notice.size == 2);

    time.value = 1200ms;
    CHECK(state.renew(left, first->uuid, 1));
    CHECK(state.source().position() == 3 && state.capture(left)->version() == 1 && notice.size == 2);
    CHECK(state.renew(left, first->uuid, 1));
    CHECK(state.source().position() == 3); // Same order changes neither deadline nor source position.
    CHECK(state.update(left, first->uuid, bytes("one"), 1));
    CHECK(state.source().position() == 4 && state.capture(left)->version() == 1 && notice.size == 2);
    CHECK(state.update(left, first->uuid, bytes("two"), 2));
    CHECK(state.source().position() == 5 && state.capture(left)->version() == 2 && notice.size == 3);
    const auto old = state.update(left, first->uuid, bytes("old"), 1);
    const auto conflict = state.update(left, first->uuid, bytes("wrong"), 2);
    CHECK(!old && old.error() == State::Error::Obsolete);
    CHECK(!conflict && conflict.error() == State::Error::Conflict);
    CHECK(state.source().position() == 5);
    const auto events = state.events(2);
    CHECK(events && events->size() == 3);
    CHECK((*events)[0].form == State::Source::Form::Renew && (*events)[1].form == State::Source::Form::Data);
    CHECK((*events)[0].record->attr == attr && (*events)[0].record->deadline == Clock::Time(2200ms));
    const auto changes = state.changes(left, 1);
    CHECK(changes && changes->size() == 1 && changes->front().data && changes->front().record->attr == attr);
    frozen->each([&](const std::string& key, const State::Content& content) { CHECK(key == first->uuid && content.attr == attr && content.data == initial); });

    time.value = 2000ms;
    state.tick();
    CHECK(state.source().position() == 6 && state.source().size() == 1);
    CHECK(state.capture(right)->size() == 0 && state.capture(right)->version() == 2);
    CHECK(state.capture(left)->size() == 1 && state.capture(left)->version() == 2);
    CHECK(state.remove(left, first->uuid));
    CHECK(state.source().position() == 7 && state.source().size() == 0 && state.capture(left)->version() == 3);
    const auto ended = state.renew(left, first->uuid, 2);
    CHECK(!ended && ended.error() == State::Error::Ended);
    CHECK(!state.find(left, first->uuid)->record && state.find(left, first->uuid)->version == 3);
    const auto recreated = state.create(left, attr, initial, 1000);
    CHECK(recreated && recreated->uuid != first->uuid && state.capture(left)->version() == 4);
    CHECK(!notice.overflow && notice.size == 6);
}

/// Final-time sampling starts new TTLs at acceptance and cannot revive registrations expiring during preparation.
void boundary() {

    Time time;
    State state([&] { return time.read(); }, {});
    const Scope scope{"time", "boundary"};
    const auto data = bytes("data");
    time.jump = 2s;
    const auto first = state.create(scope, data, data, 1000);
    CHECK(first && time.value == 3s);
    state.source().each([](const Scope&, const std::string&, const Ephemeris::Record& record) { CHECK(record.deadline == Clock::Time(4s)); });
    time.value = 3500ms;
    time.jump = 600ms;
    const auto rejected = state.renew(scope, first->uuid, 1);
    CHECK(!rejected && rejected.error() == State::Error::Ended);
    CHECK(state.events(0)->size() == 1); // Native export performs no TTL cleanup and does not imply successful renewal.
    state.tick();                        // Explicit advancement publishes authoritative deletion.
    const auto end = state.events(0);
    CHECK(end && end->size() == 2 && end->back().form == State::Source::Form::Erase && end->back().position == 2);
    CHECK(state.capture(scope)->size() == 0 && state.capture(scope)->version() == 2);

    const auto second = state.create(scope, data, data, 1000);
    CHECK(second);
    CHECK(state.renew(scope, second->uuid, 1));
    time.jump = 2s;
    const auto duplicate = state.renew(scope, second->uuid, 1);
    CHECK(!duplicate && duplicate.error() == State::Error::Ended); // Idempotent confirmation still checks expiration.
    state.tick();
    const auto position = state.source().position();
    time.ready = false;
    const auto unavailable = state.create(scope, data, data, 1000);
    CHECK(!unavailable && unavailable.error() == State::Error::Clock);
    time.ready = true; // Unreachable reference with synchronized=false still permits local leases.
    const auto local = state.create(scope, data, data, 1000);
    CHECK(local && state.source().position() == position + 1);
    time.value += 1h;
    state.tick();
    CHECK(state.source().size() == 0 && state.capture(scope)->size() == 0);
}

/// Final Data recheck rejects expiration during preparation, including same-body new orders.
void updates() {

    for (const bool same : {true, false}) {
        Time time;
        State state([&] { return time.read(); }, {});
        const Scope scope{"data", "boundary"};
        const auto original = bytes(std::string(65536, 'a'));
        const auto created = state.create(scope, original, original, 1000);
        CHECK(created);
        const auto held = state.capture(scope); // Failed updates preserve the captured complete old Data view.
        CHECK(held && held->version() == 1);

        time.value = 1500ms;
        time.jump = 500ms; // Initial check is valid; final sample reaches the exact two-second deadline.
        const auto updated = state.update(scope, created->uuid, bytes(std::string(65536, same ? 'a' : 'b')), 1);
        CHECK(!updated && updated.error() == State::Error::Ended);
        CHECK(state.events(0)->size() == 1); // Failed Data update creates no source commit.
        state.tick();                        // Expiration and export remain separate; source history contains only Create/Erase.
        const auto history = state.events(0);
        CHECK(history && history->size() == 2 && history->back().form == State::Source::Form::Erase);
        CHECK(state.capture(scope)->version() == 2 && state.capture(scope)->size() == 0 && held->version() == 1);
        held->each([&](const std::string&, const State::Content& record) { CHECK(record.data == original); });
    }
}

/// Final-time revision must reach both the native source and later multisource selection.
void deadlines() {

    /// Each local operation can revise its privately prepared absolute deadline.
    enum class Action {
        /// Replace the registration with a newer generation.
        Create,
        /// Advance Data order without changing content.
        Update,
        /// Advance the independent renewal order.
        Renew
    };

    // Each operation starts with one local candidate and prepares at 1.2 s, committing at 1.4 s.
    for (const auto action : {Action::Create, Action::Update, Action::Renew}) {
        Time time;
        State state([&] { return time.read(); }, {});
        const Scope scope{"deadline", "selection"};
        const auto attr = bytes("fixed"), data = bytes("latest");
        const auto capability = Ephemeris::capability();
        const auto uuid = Ephemeris::identity(scope, attr, 1000, capability);
        CHECK(state.create(scope, attr, data, 1000, uuid, 1, 1, capability));
        CHECK(state.admit("remote"));
        const auto frozen = state.capture(scope);
        CHECK(frozen && frozen->version() == 1);

        time.value = 1200ms;
        time.jump = 200ms;
        switch (action) {
        case Action::Create:
            CHECK(state.create(scope, attr, data, 1000, uuid, 2, 1, capability));
            break;
        case Action::Update:
            CHECK(state.update(scope, uuid, data, 2, 1, capability));
            break;
        case Action::Renew:
            CHECK(state.renew(scope, uuid, 1, 1, capability));
            break;
        }
        CHECK(time.value == 1400ms && state.source().position() == 2);
        state.source().each([](const Scope&, const std::string&, const Ephemeris::Record& record) { CHECK(record.deadline == Clock::Time(2400ms)); });

        // Joining after the preliminary 2.2 s deadline must still select the active local Data.
        time.value = 2300ms;
        const Ephemeris::Record remote{bytes("fixed"), bytes("fallback"), Clock::Time(4s), 0, 0, 1000, 3};
        CHECK(state.apply("remote", 1, scope, uuid, remote, State::Source::Form::Record));
        CHECK(state.find(scope, uuid)->record->data == data && state.capture(scope)->version() == 1);
        CHECK(state.source().position() == 2 && state.received("remote") == 1);

        // At the final deadline only the local source expires; the lower-order remote survives.
        time.value = 2400ms;
        state.tick();
        CHECK(state.source().position() == 3 && state.source().size() == 0);
        CHECK(state.find(scope, uuid)->record->data == remote.data && state.capture(scope)->version() == 2);
        CHECK(state.received("remote") == 1 && frozen->version() == 1);
        frozen->each([&](const std::string& key, const State::Content& record) { CHECK(key == uuid && record.data == data); });
    }
}

/// Shared reads preserve error mapping, create no Scope after time failure, and recover after sampler exceptions.
void reads() {

    Time time;
    time.ready = false;
    bool available = true;
    bool fail{};          // One-shot sampler exception, cleared after firing.
    State::Limits limits; // One-Scope quota exposes directory leaks on rejected reads.
    limits.scopes = 1;
    State state([&]() -> std::optional<Clock::Reading> {
        if (std::exchange(fail, false)) {
            throw std::bad_alloc{};
        }
        if (!available) {
            return std::nullopt;
        }
        return time.read();
    },
                limits);
    const Scope pending{"pending", "main"}, active{"active", "main"};
    const auto uuid = Ephemeris::uuid(); // Valid unregistered UUID keeps input validation from masking clock errors.
    CHECK(state.capture({}) == std::unexpected(State::Error::Input));
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    CHECK(state.find(pending, uuid) == std::unexpected(State::Error::Clock));
    CHECK(state.changes(pending, 0) == std::unexpected(State::Error::Clock));
    CHECK(state.events(0) && state.events(0)->empty());
    CHECK(state.deliver(0, 8, 4096)); // Source recovery is independent of public-read clock qualification.

    time.ready = fail = true;
    bool caught{}; // Require actual exception unwinding before checking lock/directory recovery.
    try {
        static_cast<void>(state.capture(pending));
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    CHECK(caught);
    for (unsigned index = 0; index < 4; ++index) {
        const Scope unknown{"unknown", std::to_string(index)};
        const auto view = state.capture(unknown);
        const auto point = state.find(unknown, uuid);
        const auto replay = state.changes(unknown, 0);
        CHECK(view && view->version() == 0 && view->size() == 0 && view->bytes() == 0);
        CHECK(point && point->version == 0 && !point->record && !point->name);
        CHECK(replay && replay->empty());
        CHECK(state.changes(unknown, 1) == std::unexpected(State::Error::Input));
    }

    time.value = 500ms;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    time.value = 750ms;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    time.value = 10s;
    time.ready = false;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    time.ready = true;
    time.value = 1s;
    available = false;
    CHECK(state.capture(pending) == std::unexpected(State::Error::Clock));
    available = true;

    const auto empty = state.capture(active);
    CHECK(empty && state.create(active, bytes("attr"), bytes("data"), 1000));
    CHECK(empty->page(0, 1, [](const auto&, const auto&) { CHECK(false); return true; }) == 0);
    CHECK(state.capture(active)->size() == 1 && state.capture(active)->version() == 1);
    CHECK(state.capture(pending)->version() == 0 && !state.find(pending, uuid)->record && state.changes(pending, 0)->empty());
    CHECK(state.create(pending, bytes("attr"), bytes("data"), 1000) == std::unexpected(State::Error::Capacity));
    CHECK(state.changes(active, 2) == std::unexpected(State::Error::Input));
    CHECK(state.events(2) == std::unexpected(State::Error::Input));
    CHECK(state.deliver(2, 8, 4096) == std::unexpected(State::Error::Input));
}

/// Final Attr/Data destruction after expiration may reenter domain; shared reads must reclaim outside the lock.
void reclaim() {

    Time time;
    bool released{}, unlocked{}; // Result flags outlive State, including exceptional cleanup.
    State::Limits limits;        // Disable both histories so only current native/projection state retains payloads.
    limits.history = limits.source.history = 0;
    const auto state = std::make_shared<State>([&] { return time.read(); }, limits);
    const Scope scope{"expiry", "reclaim"};
    Ephemeris::Value value(new Ephemeris::Buffer(16), [owner = std::weak_ptr<State>(state), &released, &unlocked](const Ephemeris::Buffer* payload) noexcept {
        released = true;
        try {
            const auto live = owner.lock(); // Avoid a State -> Value -> State strong-reference cycle.
            unlocked = live && live->received("absent") == std::unexpected(State::Error::Input);
        } catch (...) {
            unlocked = false; // Record destructor failures without throwing through noexcept.
        }
        delete payload;
    });
    CHECK(state->create(scope, value, value, 1000));
    value.reset(); // Attr/Data share one fixture payload, destroyed only after production releases all references.
    CHECK(!released);

    time.value = 2s;
    const auto view = state->capture(scope); // Unlock before reclaiming expired source/projection resources.
    CHECK(view && view->size() == 0 && released && unlocked);
}

/// Projection-capacity rejection after source preparation leaves no half-record, source position, or leaked Scope.
void capacity() {

    Time time;
    State::Limits limits;
    limits.scopes = 1;
    limits.projection.bytes = 700;
    State state([&] { return time.read(); }, limits);
    const auto oversized = std::make_shared<const Ephemeris::Buffer>(1024, 7);
    const Scope failed{"failed", "scope"};
    const Scope accepted{"accepted", "scope"};
    const auto rejected = state.create(failed, oversized, bytes("small"), 1000);
    CHECK(!rejected && rejected.error() == State::Error::Capacity);
    CHECK(state.source().position() == 0 && state.source().size() == 0);
    const auto good = state.create(accepted, bytes("a"), bytes("b"), 1000);
    CHECK(good && state.source().position() == 1);
    const auto failedUpdate = state.update(accepted, good->uuid, oversized, 1);
    CHECK(!failedUpdate && failedUpdate.error() == State::Error::Capacity);
    CHECK(state.source().position() == 1 && state.capture(accepted)->version() == 1);
    CHECK(*state.find(accepted, good->uuid)->record->data == *bytes("b"));
    CHECK(state.remove(accepted, good->uuid));
    const auto blocked = state.create(failed, bytes("a"), bytes("b"), 1000);
    CHECK(!blocked && blocked.error() == State::Error::Capacity); // Published empty Scopes retain their cursors; positions cannot be reused.
}

/// Zero history still delivers real content notifications; renewal creates none.
void history() {

    Time time;
    State::Limits limits;
    limits.history = 0;
    limits.source.history = 0;
    State state([&] { return time.read(); }, limits);
    Notice notice;
    state.notify(Notice::receive, &notice);
    const Scope scope{"zero", "history"};
    const auto first = state.create(scope, bytes("a"), bytes("b"), 1000);
    CHECK(first && notice.size == 1);
    CHECK(!state.changes(scope, 0) && state.changes(scope, 0).error() == State::Error::History);
    CHECK(!state.events(0) && state.events(0).error() == State::Error::History);
    CHECK(state.changes(scope, 1)->empty() && state.events(1)->empty());
    CHECK(state.renew(scope, first->uuid, 1) && notice.size == 1);
    CHECK(state.remove(scope, first->uuid) && notice.size == 2);
    const auto missing = state.capture(Scope{"empty", "scope"});
    CHECK(missing && missing->size() == 0 && missing->version() == 0);
}

/// Views survive State; reader callbacks may reenter live State and execute outside domain lock.
void lifetime() {

    Time time;
    const Scope scope{"view", "lifetime"};
    std::optional<State::Projection::View> old;
    {
        State state([&] { return time.read(); }, {});
        const auto first = state.create(scope, bytes("a"), bytes("b"), 1000);
        CHECK(first);
        old = *state.capture(scope);
        old->each([&](const std::string& key, const State::Content&) { CHECK(state.remove(scope, key)); });
        CHECK(state.capture(scope)->size() == 0);
    }
    std::size_t count{};
    old->each([&](const std::string&, const State::Content& content) { ++count; CHECK(*content.attr == *bytes("a") && *content.data == *bytes("b")); });
    CHECK(count == 1 && old->version() == 1);
}
} // namespace

/// Independent component fixture without networking, Pulsar, or long-running tests.
int main() {
    try {
        exports<State>([](State& state, const Scope& scope) { const auto receipt = state.create(scope, bytes("attr"), bytes("data"), 1000); CHECK(receipt); return receipt->uuid; });
        lifecycle();
        boundary();
        updates();
        deadlines();
        reads();
        reclaim();
        capacity();
        history();
        lifetime();
        std::cout << "Ephemeris state tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
