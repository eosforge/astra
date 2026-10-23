// Verify peer exchange sequencing and source recovery boundaries.
#include "check.hpp"
#include "exchange.hpp"

#include <concepts>
#include <iostream>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;
using astra::Exchange;
using astra::Scope;

/// Real native immutable Buffer, without a second fake business store.
Catalog::Value bytes(std::string_view value) {
    return std::make_shared<const Catalog::Buffer>(value.begin(), value.end());
}

/// Both real domains share controlled time without network/process workers; this fixture is not TLS regression.
struct Node {
    /// Independent node times model source-deadline/receiver-time differences.
    std::chrono::milliseconds now{1000};
    /// Real Catalog source/watermark/projection State.
    Catalog::State catalog;
    /// Real Ephemeris UUID/Attr/Data/TTL State.
    Ephemeris::State ephemeris;
    /// Recovery allowance shared by this node's logical streams.
    Exchange::Budget budget;

    Node(Catalog::State::Limits catalogLimits = {}, Ephemeris::State::Limits ephemerisLimits = {}) : catalog([this] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, catalogLimits), ephemeris([this] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, ephemerisLimits) {}

    /// Readmission of the same identity is idempotent; a new stream preserves installed contiguous positions.
    std::unique_ptr<Exchange> connect(std::string peer, astra::Steady::time_point time) {
        CHECK(catalog.admit(peer) && ephemeris.admit(peer));
        return std::make_unique<Exchange>(catalog, ephemeris, std::move(peer), budget, 8 * 1024 * 1024, time);
    }
};

/// Connect real SessionPackets. Take models StartWrite handoff; receive performs complete source recovery.
bool transfer(Exchange& from, Exchange& to, astra::Steady::time_point time) {
    const auto prepared = from.prepare(time);
    CHECK(prepared);
    if (!*prepared) {
        return false;
    }
    auto packet = from.take();
    CHECK(packet.ByteSizeLong() <= 8 * 1024 * 1024);
    CHECK(to.receive(packet, time));
    return true;
}

/// Bound exchanges so ACK-of-ACK or empty-packet storms cannot loop indefinitely.
void drain(Exchange& left, Exchange& right, astra::Steady::time_point time) {
    for (unsigned iteration = 0; iteration != 2048; ++iteration) {
        const bool first = transfer(left, right, time);
        const bool second = transfer(right, left, time);
        if (!first && !second) {
            CHECK(left.pending() || right.pending() || (left.ready() && right.ready())); // Report local installation work without relying on blind polling when no packet progresses.
            if (!left.pending() && !right.pending()) {
                return;
            }
        }
    }
    throw std::runtime_error("Peer data did not settle within bounded transfers");
}

/// Empty-source startup, bidirectional local commits, renewal-only visibility, and no replica rebroadcast.
void bidirectional() {

    Node left, right;
    const auto time = astra::Steady::now();
    const Scope scope{"scope", "main"};
    {
        auto a = left.connect("b", time), b = right.connect("a", time);
        drain(*a, *b, time);
        CHECK(right.catalog.publish(scope, "right", bytes("r"), 1, 10000));
        CHECK(left.catalog.publish(scope, "left", bytes("l"), 1, 10000));
        const auto registration = left.ephemeris.create(scope, bytes("attr"), bytes("data"), 10000);
        CHECK(registration);
        drain(*a, *b, time);
        CHECK(left.catalog.capture(scope)->size() == 2 && right.catalog.capture(scope)->size() == 2);
        CHECK(right.ephemeris.find(scope, registration->uuid)->record);
        CHECK(left.catalog.source().position() == 1 && right.catalog.source().position() == 1 && right.ephemeris.source().position() == 0);
        const auto catalogVersion = right.catalog.capture(scope)->version();
        const auto ephemerisVersion = right.ephemeris.capture(scope)->version();
        left.now += 100ms;
        CHECK(left.catalog.renew(scope, "left", 1, 10000));
        CHECK(left.ephemeris.renew(scope, registration->uuid, 1));
        drain(*a, *b, time + 100ms);
        CHECK(right.catalog.capture(scope)->version() == catalogVersion && right.ephemeris.capture(scope)->version() == ephemerisVersion);
        CHECK(left.ephemeris.update(scope, registration->uuid, bytes("changed"), 1));
        drain(*a, *b, time + 200ms);
        CHECK(*right.ephemeris.find(scope, registration->uuid)->record->data == *bytes("changed"));
        CHECK(left.ephemeris.remove(scope, registration->uuid));
        drain(*a, *b, time + 300ms);
        CHECK(!right.ephemeris.find(scope, registration->uuid)->record);
    }
    CHECK(left.budget.used == 0 && right.budget.used == 0);
}

/// After replica TTL, deadline/Data-only input repairs the complete row on the same stream before confirmation, preserving other Scopes.
void repair() {

    Node left, right;
    const auto time = astra::Steady::now();
    const Scope one{"one", "main"}, two{"two", "main"};
    CHECK(left.catalog.publish(one, "key", bytes("body"), 4, 1000));
    const auto registration = left.ephemeris.create(one, bytes("attr"), bytes("data"), 1000);
    CHECK(registration);
    auto a = left.connect("b", time), b = right.connect("a", time);
    drain(*a, *b, time);
    right.now = 2100ms;
    right.catalog.tick();
    right.ephemeris.tick();
    CHECK(!right.catalog.find(one, "key")->record && !right.ephemeris.find(one, registration->uuid)->record);
    left.now = 1500ms;
    CHECK(left.catalog.renew(one, "key", 4, 5000));
    CHECK(left.catalog.publish(two, "other", bytes("other"), 1, 5000));
    CHECK(left.ephemeris.update(one, registration->uuid, bytes("new"), 1));
    CHECK(left.ephemeris.renew(one, registration->uuid, 1));
    const auto other = left.ephemeris.create(two, bytes("attr"), bytes("other"), 5000);
    CHECK(other);
    drain(*a, *b, time + 1s);
    CHECK(right.catalog.find(one, "key")->record->version == 4 && right.catalog.find(two, "other")->record);
    CHECK(right.catalog.received("a") == left.catalog.source().position());
    CHECK(*right.ephemeris.find(one, registration->uuid)->record->attr == *bytes("attr"));
    CHECK(*right.ephemeris.find(one, registration->uuid)->record->data == *bytes("new"));
    CHECK(right.ephemeris.find(two, other->uuid)->record && right.ephemeris.received("a") == left.ephemeris.source().position());
}

/// Zero history forces source baseline recovery; reconnection resumes installed positions and an empty baseline clears only its own Ephemeris source.
void snapshot() {

    Catalog::State::Limits catalogLimits;
    Ephemeris::State::Limits ephemerisLimits;
    catalogLimits.source.history = ephemerisLimits.source.history = 0;
    Node left(catalogLimits, ephemerisLimits), right;
    const auto time = astra::Steady::now();
    const Scope scope{"source", "main"};
    for (unsigned index = 0; index != 300; ++index) {
        CHECK(left.catalog.publish(scope, std::to_string(index), bytes("v"), index + 1, 10000));
    }
    CHECK(left.catalog.publish({"a", "main"}, "first", bytes("v"), 1, 10000)); // Three-Scope recovery requires internal rounds without network packets.
    CHECK(left.catalog.publish({"z", "main"}, "last", bytes("v"), 1, 10000));
    const auto registration = left.ephemeris.create(scope, bytes("attr"), bytes("remote"), 10000);
    const auto own = right.ephemeris.create(scope, bytes("own"), bytes("own"), 10000);
    CHECK(registration && own);
    {
        auto a = left.connect("b", time), b = right.connect("a", time);
        drain(*a, *b, time);
        CHECK(right.catalog.capture(scope)->size() == 300 && right.ephemeris.capture(scope)->size() == 2);
    }
    CHECK(left.budget.used == 0 && right.budget.used == 0);
    CHECK(left.ephemeris.remove(scope, registration->uuid));
    CHECK(left.catalog.publish(scope, "new", bytes("new"), 1, 10000));
    {
        auto a = left.connect("b", time + 1s), b = right.connect("a", time + 1s);
        drain(*a, *b, time + 1s);
        CHECK(right.catalog.capture(scope)->size() == 301);
        CHECK(!right.ephemeris.find(scope, registration->uuid)->record && right.ephemeris.find(scope, own->uuid)->record);
    }
    CHECK(left.budget.used == 0 && right.budget.used == 0);
}

/// Whole-packet validation prevents a valid prefix from installing before malformed later input; capacity rejection preserves installed baselines.
void rejection() {

    Node node;
    const auto time = astra::Steady::now();
    const Scope scope{"one", "main"};
    {
        auto receiver = node.connect("source", time);
        Exchange::Packet packet;
        auto* changes = packet.mutable_catalog_changes();
        changes->set_head(2);
        auto* first = changes->add_entries();
        first->set_position(1);
        astra::Parcel::scope(*first->mutable_scope(), scope);
        first->set_key("key");
        astra::Parcel::record(*first->mutable_record(), Catalog::Record{1, bytes("v"), Clock::Time(10s)});
        changes->add_entries()->CopyFrom(*first);
        changes->mutable_entries(1)->set_position(2);
        changes->mutable_entries(1)->clear_action();
        CHECK(!receiver->receive(packet, time));
        CHECK(node.catalog.received("source") == 0 && !node.catalog.find(scope, "key")->record);
        node.budget.maximum = 1024;
        packet.Clear();
        packet.mutable_catalog_snapshot()->set_position(1);
        packet.mutable_catalog_snapshot()->set_complete(true);
        const auto rejected = receiver->receive(packet, time);
        CHECK(!rejected && rejected.error().code == astra::Status::Code::Capacity && node.catalog.received("source") == 0);
    }
    CHECK(node.budget.used == 0);
    {
        auto receiver = node.connect("source", time);
        Exchange::Packet repair; // Continuous peer repair requests cannot bypass this side's incomplete-recovery deadline.
        auto* request = repair.mutable_repair();
        request->set_domain(proto::astra::v1::DOMAIN_CATALOG);
        astra::Parcel::scope(*request->mutable_scope(), scope);
        request->set_key("absent");
        request->set_trigger(1);
        request->set_version(1);
        CHECK(node.catalog.publish(scope, "other", bytes("v"), 1, 10000));
        CHECK(receiver->receive(repair, time));
        const auto timeout = receiver->prepare(time + 31s);
        CHECK(!timeout && timeout.error().code == astra::Status::Code::Timeout);
    }
    CHECK(node.budget.used == 0);
}

/// Both domains cover bad first pages, partial candidates, native capacity, and retirement before installation. Failure returns workspace before stream destruction.
template <typename Domain>
void discarded() {

    const Scope scope{"discarded", "main"};
    const auto time = astra::Steady::now();
    // Modes: empty incomplete first page, duplicate key, second-record capacity overflow, retirement before complete.
    for (unsigned mode = 0; mode != 4; ++mode) {
        Catalog::State::Limits catalog;
        Ephemeris::State::Limits ephemeris;
        catalog.source.records = ephemeris.source.records = 1;
        Node node(catalog, ephemeris);
        auto& state = [&]() -> typename Domain::State& { if constexpr (std::same_as<Domain, Catalog>){ return node.catalog;
} else{ return node.ephemeris;
} }();
        constexpr std::size_t reserved = 4096; // Another receiver's allowance must not be released by this stream's failure.
        CHECK(node.budget.acquire(reserved));
        auto receiver = node.connect("source", time); // Keep the stream alive to verify immediate budget return.
        Exchange::Packet packet;
        auto& page = [&]() -> auto& { if constexpr (std::same_as<Domain, Catalog>){ return *packet.mutable_catalog_snapshot();
} else{ return *packet.mutable_ephemeris_snapshot();
} }();
        page.set_position(1);

        if (mode != 0) {
            auto* entry = page.add_entries(); // First row remains private and cannot change the public source.
            astra::Parcel::scope(*entry->mutable_scope(), scope);
            if constexpr (std::same_as<Domain, Catalog>) {
                entry->set_key("first");
                astra::Parcel::record(*entry->mutable_record(), Catalog::Record{1, bytes("data"), Clock::Time(10s)});
            } else {
                entry->set_uuid(Ephemeris::uuid());
                astra::Parcel::record(*entry->mutable_record(), Ephemeris::Record{bytes("attr"), bytes("data"), Clock::Time(10s), 0, 0, 1000});
            }
            CHECK(receiver->receive(packet, time));
            CHECK(node.budget.used == reserved + 64 * 1024 * 1024);
            CHECK(state.received("source") == 0 && state.capture(scope)->size() == 0);
            page.set_complete(true);
            if (mode == 2) {
                if constexpr (std::same_as<Domain, Catalog>) {
                    page.mutable_entries(0)->set_key("second");
                } else {
                    page.mutable_entries(0)->set_uuid(Ephemeris::uuid());
                }
            } else if (mode == 3) {
                page.clear_entries(); // A complete body still fails final restore after admission revocation.
                state.retire("source");
            }
        }

        const auto rejected = receiver->receive(packet, time);
        CHECK(!rejected);
        CHECK(rejected.error().code == (mode == 2 ? astra::Status::Code::Capacity : astra::Status::Code::Protocol));
        CHECK(node.budget.used == reserved && state.capture(scope)->size() == 0);
        receiver.reset(); // Destruction cannot release allowance already returned by failure handling.
        CHECK(node.budget.used == reserved);
        node.budget.release(reserved);
    }
}

/// Insufficient global workspace installs no partial data and releases reservations, without injecting internal-accounting corruption.
void backlog() {

    Node node;
    const auto time = astra::Steady::now();
    const Scope scope{"one", "main"};
    auto receiver = node.connect("source", time);
    Exchange::Packet packet;
    auto* changes = packet.mutable_catalog_changes();
    changes->set_head(1);
    auto* entry = changes->add_entries();
    entry->set_position(1);
    astra::Parcel::scope(*entry->mutable_scope(), scope);
    entry->set_key("key");
    astra::Parcel::record(*entry->mutable_record(), Catalog::Record{1, bytes("v"), Clock::Time(10s)});
    node.budget.maximum = 1;
    const auto refused = receiver->receive(packet, time);
    CHECK(!refused && refused.error().code == astra::Status::Code::Capacity && node.catalog.received("source") == 0 && !node.catalog.find(scope, "key")->record);
    CHECK(node.budget.used == 0);
}
} // namespace

/// Packet-loop component fixture without actual gRPC; process tests separately cover network faults.
int main() {

    try {
        bidirectional();
        repair();
        snapshot();
        rejection();
        discarded<Catalog>();
        discarded<Ephemeris>();
        backlog();
        std::cout << "peer exchanges: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
