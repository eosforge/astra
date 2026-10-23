// Verify bounded snapshot and delta page construction at protocol limits.
#include "check.hpp"
#include "dispatch.hpp"
#include "landing.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace {
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;
using astra::Parcel;
using astra::Scope;
using namespace std::chrono_literals;

/// Own literal binary test data independently of protocol encoding.
Catalog::Value bytes(std::string_view value) {
    return std::make_shared<const Catalog::Buffer>(value.begin(), value.end());
}

/// Associate each malformed input with a stable, independently specified boundary name.
template <typename Message>
using Damage = std::pair<std::string_view, void (*)(Message&)>;

/// Emit an individual witness only after the expected acceptance or rejection is actually checked.
void witness(std::string_view name, bool actual, bool expected) {

    CHECK(actual == expected);
    std::cout << "ASTRA-PARCEL " << name << ' ' << actual << '\n';
}

/// Change one field of an admitted message, preserving the independent expected rejection.
template <typename Message, std::size_t Size, typename Query>
void refuse(const Message& original, const std::array<Damage<Message>, Size>& cases, Query query) {

    for (const auto& [name, change] : cases) {
        auto message = original;
        change(message);
        witness(name, query(message), false);
    }
}

/// Require the exact internal-contract error rather than counting unrelated exceptions as rejection.
template <typename Action>
void reject(std::string_view name, std::string_view expected, Action action) {

    bool rejected{};
    try {
        action();
    } catch (const std::logic_error& error) {
        CHECK(error.what() == expected);
        rejected = true;
    }
    witness(name, rejected, true);
}

/// Return one fixed RFC-variant UUID-v4 vector without calling the production identifier generator.
std::string uuid() {

    std::string value(16, '\0');
    value[6] = '\x40';
    value[8] = '\x80';
    return value;
}

/// Check incoming scopes and both record domains against literal wire limits and decoded fields.
void records() {

    proto::astra::v1::Scope address;
    address.set_sector(std::string(128, 's'));
    address.set_spectrum(std::string(128, 'p'));
    const auto decoded = Parcel::scope(address);
    CHECK(decoded && decoded->sector == std::string(128, 's') && decoded->spectrum == std::string(128, 'p'));
    const std::array<Damage<proto::astra::v1::Scope>, 5> addresses{{
        {"scope.sector-empty", [](auto& value) { value.clear_sector(); }},
        {"scope.spectrum-empty", [](auto& value) { value.clear_spectrum(); }},
        {"scope.sector-long", [](auto& value) { value.set_sector(std::string(129, 's')); }},
        {"scope.spectrum-long", [](auto& value) { value.set_spectrum(std::string(129, 'p')); }},
        {"scope.utf8", [](auto& value) { value.set_sector("\xed\xa0\x80"); }},
    }};
    refuse(address, addresses, [](const auto& value) { return Parcel::scope(value).has_value(); });

    proto::astra::v1::CatalogRecord catalog;
    catalog.set_version(UINT64_MAX);
    catalog.mutable_value()->set_deadline(INT64_MAX);
    const auto empty = Parcel::record(catalog);
    CHECK(empty && empty->version == UINT64_MAX && empty->value && empty->value->empty() && empty->deadline == Clock::Time(std::chrono::nanoseconds(INT64_MAX)));
    catalog.mutable_value()->set_value(std::string(1024 * 1024, 'v'));
    CHECK(Parcel::record(catalog)->value->size() == 1024 * 1024);
    const std::array<Damage<proto::astra::v1::CatalogRecord>, 5> catalogs{{
        {"catalog.record.version", [](auto& value) { value.set_version(0); }},
        {"catalog.record.body", [](auto& value) { value.clear_value(); }},
        {"catalog.record.deadline-zero", [](auto& value) { value.mutable_value()->set_deadline(0); }},
        {"catalog.record.deadline-overflow", [](auto& value) { value.mutable_value()->set_deadline(UINT64_MAX); }},
        {"catalog.record.value-long", [](auto& value) { value.mutable_value()->set_value(std::string(1024 * 1024 + 1, 'v')); }},
    }};
    refuse(catalog, catalogs, [](const auto& value) { return Parcel::record(value).has_value(); });
    catalog.mutable_watermark();
    const auto watermark = Parcel::record(catalog);
    CHECK(watermark && watermark->version == UINT64_MAX && !watermark->value && !watermark->deadline);

    proto::astra::v1::EphemerisRecord ephemeris;
    ephemeris.set_deadline(1);
    ephemeris.set_ttl_ms(1000);
    const auto zero = Parcel::record(ephemeris);
    CHECK(zero && zero->attr && zero->attr->empty() && zero->data && zero->data->empty());
    CHECK(zero->deadline == Clock::Time(1ns) && zero->ttl == 1000 && zero->update == 0 && zero->renewal == 0 && zero->generation == 0);
    ephemeris.set_attr(std::string(1024 * 1024, 'a'));
    ephemeris.set_data(std::string(1024 * 1024, 'd'));
    ephemeris.set_deadline(INT64_MAX);
    ephemeris.set_ttl_ms(600000);
    ephemeris.set_update(3);
    ephemeris.set_renewal(5);
    ephemeris.set_generation(7);
    const auto maximum = Parcel::record(ephemeris);
    CHECK(maximum && maximum->attr->size() == 1024 * 1024 && maximum->data->size() == 1024 * 1024);
    CHECK(maximum->ttl == 600000 && maximum->update == 3 && maximum->renewal == 5 && maximum->generation == 7);
    const std::array<Damage<proto::astra::v1::EphemerisRecord>, 6> ephemerides{{
        {"ephemeris.record.attr-long", [](auto& value) { value.set_attr(std::string(1024 * 1024 + 1, 'a')); }},
        {"ephemeris.record.data-long", [](auto& value) { value.set_data(std::string(1024 * 1024 + 1, 'd')); }},
        {"ephemeris.record.ttl-low", [](auto& value) { value.set_ttl_ms(999); }},
        {"ephemeris.record.ttl-high", [](auto& value) { value.set_ttl_ms(600001); }},
        {"ephemeris.record.deadline-zero", [](auto& value) { value.set_deadline(0); }},
        {"ephemeris.record.deadline-overflow", [](auto& value) { value.set_deadline(UINT64_MAX); }},
    }};
    refuse(ephemeris, ephemerides, [](const auto& value) { return Parcel::record(value).has_value(); });
}

/// Reject invalid native records and source events at their documented encoder boundaries.
void events() {

    using CatalogSource = astra::Origin<Catalog::Record>;
    using EphemerisSource = astra::Origin<Ephemeris::Record, true>;
    const auto scope = std::make_shared<const Scope>(Scope{"routes", "main"});
    const Catalog::Record catalog{1, bytes("v"), Clock::Time(1ns)};
    const Ephemeris::Record ephemeris{bytes("a"), bytes("d"), Clock::Time(1ns), 2, 3, 1000, 4};
    const std::array<Damage<Catalog::Record>, 5> catalogs{{
        {"catalog.native.version", [](auto& value) { value.version = 0; }},
        {"catalog.native.no-value", [](auto& value) { value.value.reset(); }},
        {"catalog.native.no-deadline", [](auto& value) { value.deadline.reset(); }},
        {"catalog.native.value-long", [](auto& value) { value.value = bytes(std::string(1024 * 1024 + 1, 'v')); }},
        {"catalog.native.deadline", [](auto& value) { value.deadline = Clock::Time(-1ns); }},
    }};
    for (const auto& [name, change] : catalogs) {
        auto value = catalog;
        change(value);
        reject(name, "Invalid native Catalog record", [&value] { proto::astra::v1::CatalogRecord message; Parcel::record(message, value); });
    }
    const std::array<Damage<Ephemeris::Record>, 8> ephemerides{{
        {"ephemeris.native.no-attr", [](auto& value) { value.attr.reset(); }},
        {"ephemeris.native.no-data", [](auto& value) { value.data.reset(); }},
        {"ephemeris.native.attr-long", [](auto& value) { value.attr = bytes(std::string(1024 * 1024 + 1, 'a')); }},
        {"ephemeris.native.data-long", [](auto& value) { value.data = bytes(std::string(1024 * 1024 + 1, 'd')); }},
        {"ephemeris.native.ttl-low", [](auto& value) { value.ttl = 999; }},
        {"ephemeris.native.ttl-high", [](auto& value) { value.ttl = 600001; }},
        {"ephemeris.native.deadline-zero", [](auto& value) { value.deadline = Clock::Time(0ns); }},
        {"ephemeris.native.deadline-negative", [](auto& value) { value.deadline = Clock::Time(-1ns); }},
    }};
    for (const auto& [name, change] : ephemerides) {
        auto value = ephemeris;
        change(value);
        reject(name, "Invalid native Ephemeris record", [&value] { proto::astra::v1::EphemerisRecord message; Parcel::record(message, value); });
    }
    const CatalogSource::Event publication{std::make_shared<const CatalogSource::Name>(CatalogSource::Name{scope, "key"}), catalog, 1};
    proto::astra::v1::CatalogDelta published;
    Parcel::delta(published, publication);
    CHECK(published.has_record() && published.record().version() == 1 && published.record().value().value() == "v");
    CHECK(published.position() == 1 && published.key() == "key" && published.scope().sector() == "routes" && published.scope().spectrum() == "main");
    auto renewed = publication;
    renewed.form = CatalogSource::Form::Renew;
    Parcel::delta(published, renewed);
    CHECK(published.has_lease() && published.lease().version() == 1 && published.lease().deadline() == 1);
    renewed.form = CatalogSource::Form::Record;
    renewed.record = Catalog::Record{2, {}, {}};
    Parcel::delta(published, renewed);
    CHECK(published.has_record() && published.record().version() == 2 && published.record().has_watermark() && !published.has_lease());
    const std::array<Damage<CatalogSource::Event>, 7> publications{{
        {"catalog.event.no-name", [](auto& value) { value.name.reset(); }},
        {"catalog.event.no-scope", [](auto& value) { value.name = std::make_shared<const CatalogSource::Name>(CatalogSource::Name{{}, "key"}); }},
        {"catalog.event.scope", [](auto& value) { value.name = std::make_shared<const CatalogSource::Name>(CatalogSource::Name{std::make_shared<const Scope>(Scope{"", "main"}), "key"}); }},
        {"catalog.event.key", [](auto& value) { value.name = std::make_shared<const CatalogSource::Name>(CatalogSource::Name{value.name->scope, std::string(1, '\0')}); }},
        {"catalog.event.position", [](auto& value) { value.position = 0; }},
        {"catalog.event.no-record", [](auto& value) { value.record.reset(); }},
        {"catalog.event.record", [](auto& value) { value.record->version = 0; }},
    }};
    for (const auto& [name, change] : publications) {
        auto value = publication;
        change(value);
        reject(name, "Invalid Catalog source event", [&value] { proto::astra::v1::CatalogDelta message; Parcel::delta(message, value); });
    }
    for (const auto form : {CatalogSource::Form::Data, CatalogSource::Form::Erase, CatalogSource::Form::Renew}) {
        auto value = publication;
        value.form = form;
        value.record = Catalog::Record{1, {}, {}};
        reject(form == CatalogSource::Form::Data ? "catalog.event.data" : form == CatalogSource::Form::Erase ? "catalog.event.erase"
                                                                                                             : "catalog.event.empty-lease",
               "Catalog source has an unsupported operation", [&value] { proto::astra::v1::CatalogDelta message; Parcel::delta(message, value); });
    }

    const EphemerisSource::Event beacon{std::make_shared<const EphemerisSource::Name>(EphemerisSource::Name{scope, uuid()}), ephemeris, 1};
    proto::astra::v1::EphemerisDelta beamed;
    for (const auto form : {EphemerisSource::Form::Record, EphemerisSource::Form::Data, EphemerisSource::Form::Renew, EphemerisSource::Form::Erase}) {
        auto value = beacon;
        value.form = form;
        if (form == EphemerisSource::Form::Erase) {
            value.record.reset();
        }
        Parcel::delta(beamed, value);
        CHECK(beamed.position() == 1 && beamed.uuid() == uuid() && beamed.scope().sector() == "routes" && beamed.scope().spectrum() == "main");
        if (form == EphemerisSource::Form::Record) {
            CHECK(beamed.has_record() && beamed.record().attr() == "a" && beamed.record().data() == "d" && beamed.record().ttl_ms() == 1000 && beamed.record().generation() == 4);
        }
        if (form == EphemerisSource::Form::Data) {
            CHECK(beamed.has_data() && beamed.data().data() == "d" && beamed.data().order() == 2 && beamed.data().deadline() == 1);
        }
        if (form == EphemerisSource::Form::Renew) {
            CHECK(beamed.has_lease() && beamed.lease().order() == 3 && beamed.lease().deadline() == 1);
        }
        if (form == EphemerisSource::Form::Erase) {
            CHECK(beamed.has_erase() && !beamed.has_record() && !beamed.has_data() && !beamed.has_lease());
        }
    }
    const std::array<Damage<EphemerisSource::Event>, 7> beacons{{
        {"ephemeris.event.no-name", [](auto& value) { value.name.reset(); }},
        {"ephemeris.event.no-scope", [](auto& value) { value.name = std::make_shared<const EphemerisSource::Name>(EphemerisSource::Name{{}, uuid()}); }},
        {"ephemeris.event.scope", [](auto& value) { value.name = std::make_shared<const EphemerisSource::Name>(EphemerisSource::Name{std::make_shared<const Scope>(Scope{"routes", ""}), uuid()}); }},
        {"ephemeris.event.uuid", [](auto& value) { value.name = std::make_shared<const EphemerisSource::Name>(EphemerisSource::Name{value.name->scope, std::string(16, '\0')}); }},
        {"ephemeris.event.position", [](auto& value) { value.position = 0; }},
        {"ephemeris.event.no-record", [](auto& value) { value.record.reset(); }},
        {"ephemeris.event.erase-record", [](auto& value) { value.form = EphemerisSource::Form::Erase; }},
    }};
    for (const auto& [name, change] : beacons) {
        auto value = beacon;
        change(value);
        reject(name, "Invalid Ephemeris source event", [&value] { proto::astra::v1::EphemerisDelta message; Parcel::delta(message, value); });
    }
    for (unsigned index = 0; index < 5; ++index) {
        auto value = beacon;
        value.form = index < 2 ? EphemerisSource::Form::Data : EphemerisSource::Form::Renew;
        if (index == 0) {
            value.record->data.reset();
        }
        if (index == 1) {
            value.record->update = 0;
        }
        if (index == 2) {
            value.record->renewal = 0;
        }
        if (index == 3) {
            value.record->deadline = Clock::Time(0ns);
        }
        if (index == 4) {
            value.record->deadline = Clock::Time(-1ns);
        }
        constexpr std::array<std::string_view, 5> names{"ephemeris.event.data-absent", "ephemeris.event.data-order", "ephemeris.event.lease-order", "ephemeris.event.lease-zero", "ephemeris.event.lease-negative"};
        reject(names[index], index < 2 ? "Invalid Ephemeris data event" : "Invalid Ephemeris lease event", [&value] { proto::astra::v1::EphemerisDelta message; Parcel::delta(message, value); });
    }
}

/// Exercise both incoming delta envelopes independently of the production encoder.
template <typename Message>
void frames() {

    constexpr bool catalog = std::is_same_v<Message, proto::astra::v1::CatalogChanges>;
    const std::string prefix = catalog ? "catalog.frame." : "ephemeris.frame.";
    Message message;
    witness(prefix + "empty", Parcel::valid(message), true);
    const auto append = [](Message& value, std::uint64_t position) {
        auto* entry = value.add_entries();
        entry->mutable_scope()->set_sector("routes");
        entry->mutable_scope()->set_spectrum("main");
        entry->set_position(position);
        if constexpr (catalog) {
            entry->set_key("key");
            entry->mutable_record()->set_version(1);
            entry->mutable_record()->mutable_watermark();
        } else {
            entry->set_uuid(uuid());
            entry->mutable_erase();
        }
    };
    message.set_head(2);
    append(message, 1);
    append(message, 2);
    witness(prefix + "continuous", Parcel::valid(message), true);
    for (unsigned index = 0; index < 9; ++index) {
        auto bad = message;
        auto* first = bad.mutable_entries(0);
        auto* last = bad.mutable_entries(1);
        if (index == 0) {
            first->mutable_scope()->clear_sector();
        }
        if (index == 1) {
            first->mutable_scope()->clear_spectrum();
        }
        if (index == 2) {
            first->set_position(0);
        }
        if (index == 3) {
            bad.set_head(1);
        }
        if (index == 4) {
            last->set_position(1);
        }
        if (index == 5) {
            bad.set_head(3);
            last->set_position(3);
        }
        if (index == 6) {
            first->set_position(UINT64_MAX);
            last->set_position(UINT64_MAX);
            bad.set_head(UINT64_MAX);
        }
        if (index == 7) {
            if constexpr (catalog) {
                first->clear_key();
            } else {
                first->set_uuid(std::string(15, '\0'));
            }
        }
        if (index == 8) {
            if constexpr (catalog) {
                first->clear_record();
            } else {
                first->clear_erase();
            }
        }
        constexpr std::array<std::string_view, 9> names{"sector", "spectrum", "zero", "future", "duplicate", "gap", "overflow", "key", "body"};
        witness(prefix + std::string(names[index]), Parcel::valid(bad), false);
    }
    message.clear_entries();
    message.set_head(UINT64_MAX);
    append(message, UINT64_MAX);
    witness(prefix + "last-position", Parcel::valid(message), true);
    message.clear_entries();
    message.set_head(257);
    for (unsigned index = 1; index <= 256; ++index) {
        append(message, index);
    }
    witness(prefix + "count-limit", Parcel::valid(message), true);
    append(message, 257);
    witness(prefix + "count-overflow", Parcel::valid(message), false);
    message.clear_entries();
    for (unsigned index = 1; index <= 8; ++index) {
        append(message, index);
        if constexpr (catalog) {
            auto* record = message.mutable_entries(static_cast<int>(index - 1))->mutable_record();
            record->mutable_value()->set_value(std::string(1024 * 1024, 'v'));
            record->mutable_value()->set_deadline(1);
        } else {
            auto* data = message.mutable_entries(static_cast<int>(index - 1))->mutable_data();
            data->set_data(std::string(1024 * 1024, 'd'));
            data->set_order(1);
        }
    }
    CHECK(message.entries_size() == 8 && message.ByteSizeLong() > 8 * 1024 * 1024);
    witness(prefix + "bytes-overflow", Parcel::valid(message), false);
    message.clear_entries();
    append(message, 1);
    auto* entry = message.mutable_entries(0);
    if constexpr (catalog) {
        entry->mutable_record()->set_version(0);
        witness(prefix + "record-invalid", Parcel::valid(message), false);
        entry->mutable_lease()->set_version(1);
        entry->mutable_lease()->set_deadline(1);
        witness(prefix + "lease", Parcel::valid(message), true);
        entry->mutable_lease()->set_version(0);
        witness(prefix + "lease-version", Parcel::valid(message), false);
        entry->mutable_lease()->set_version(1);
        entry->mutable_lease()->set_deadline(0);
        witness(prefix + "lease-zero", Parcel::valid(message), false);
        entry->mutable_lease()->set_deadline(UINT64_MAX);
        witness(prefix + "lease-overflow", Parcel::valid(message), false);
    } else {
        entry->mutable_record()->set_deadline(1);
        entry->mutable_record()->set_ttl_ms(1000);
        witness(prefix + "record", Parcel::valid(message), true);
        entry->mutable_record()->set_ttl_ms(999);
        witness(prefix + "record-invalid", Parcel::valid(message), false);
        entry->mutable_data()->set_order(1);
        witness(prefix + "data-no-deadline", Parcel::valid(message), true);
        entry->mutable_data()->set_deadline(INT64_MAX);
        witness(prefix + "data-deadline", Parcel::valid(message), true);
        entry->mutable_data()->set_deadline(UINT64_MAX);
        witness(prefix + "data-overflow", Parcel::valid(message), false);
        entry->mutable_data()->set_deadline(0);
        entry->mutable_data()->set_order(0);
        witness(prefix + "data-order", Parcel::valid(message), false);
        entry->mutable_data()->set_order(1);
        entry->mutable_data()->set_data(std::string(1024 * 1024 + 1, 'd'));
        witness(prefix + "data-long", Parcel::valid(message), false);
        entry->mutable_lease()->set_order(1);
        entry->mutable_lease()->set_deadline(1);
        witness(prefix + "lease", Parcel::valid(message), true);
        entry->mutable_lease()->set_order(0);
        witness(prefix + "lease-order", Parcel::valid(message), false);
        entry->mutable_lease()->set_order(1);
        entry->mutable_lease()->set_deadline(0);
        witness(prefix + "lease-zero", Parcel::valid(message), false);
        entry->mutable_lease()->set_deadline(UINT64_MAX);
        witness(prefix + "lease-overflow", Parcel::valid(message), false);
    }
}

/// Immutable binary fixture value, including owned empty bytes.
/// Empty prefixes, contiguous packing, and cumulative ACK distinguish preparation from network handoff without per-item round trips.
void catalog() {

    auto now = 1000ms; // Controlled business time without time/network workers.
    Catalog::State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    astra::Dispatch<Catalog> stream(state);
    CHECK(!stream.prepare() && !stream.acknowledge(0));
    CHECK(stream.resume(0) && !stream.resume(0));
    auto packet = stream.prepare();
    CHECK(packet && *packet && (*packet)->has_catalog_changes());
    CHECK((*packet)->catalog_changes().head() == 0 && (*packet)->catalog_changes().entries().empty());
    stream.dispatched(); // Empty groups confirm once, then produce no duplicate idle packets.
    CHECK(stream.prepare() && *stream.prepare() == nullptr);
    CHECK(state.publish({"routes", "one"}, "key", bytes(std::string("a\0b", 3)), 90, 1000));
    CHECK(state.publish({"routes", "two"}, "key", bytes(""), 5, 1000));
    CHECK(state.renew({"routes", "one"}, "key", 90, 2000));
    packet = stream.prepare();
    CHECK(packet && *packet && (*packet)->catalog_changes().entries_size() == 3);
    CHECK(Parcel::valid((*packet)->catalog_changes()));
    CHECK(!stream.acknowledge(3) && stream.sent() == 0);
    CHECK(stream.prepare().value() == *packet); // Repeated prepare borrows the same frozen packet without advancing position.
    const auto sent = stream.dispatched();
    const auto& entries = sent.catalog_changes().entries();
    CHECK(entries[0].position() == 1 && entries[0].record().version() == 90);
    CHECK(entries[0].record().value().value() == std::string("a\0b", 3));
    CHECK(entries[1].has_record() && entries[1].record().value().value().empty());
    CHECK(entries[2].has_lease() && !entries[2].has_record() && entries[2].lease().version() == 90);
    CHECK(stream.sent() == 3 && stream.acknowledged() == 0);
    CHECK(stream.acknowledge(2) && stream.acknowledge(3) && stream.acknowledge(3));
    CHECK(!stream.acknowledge(2) && !stream.acknowledge(4));

    // Preparation discovers the last write from the actual source head even without another notification.
    CHECK(state.publish({"routes", "one"}, "key", bytes("next"), 100, 1000));
    packet = stream.prepare();
    CHECK(packet && *packet && (*packet)->catalog_changes().entries_size() == 1);
    CHECK((*packet)->catalog_changes().entries(0).position() == 4);
    astra::Dispatch<Catalog> future(state);
    CHECK(!future.resume(5) && future.resume(4)); // Rejected future recovery preserves the ability to start correctly, without resetting silently to zero.
}

/// Pruned history uses one cross-Scope baseline; concurrent new facts follow it.
void baseline() {

    auto now = 1000ms;
    Catalog::State::Limits limits;
    limits.source.history = 0;
    Catalog::State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, limits);
    const auto payload = bytes(std::string(400, 'x'));
    CHECK(state.publish({"routes", "one"}, "first", payload, 1, 1000));
    CHECK(state.publish({"routes", "two"}, "second", payload, 7, 1000));
    astra::Dispatch<Catalog> stream(state, 2048, 256); // One valid row above the soft target occupies its own page.
    CHECK(stream.resume(0));
    const auto first = stream.prepare();
    CHECK(first && *first && (*first)->has_catalog_snapshot());
    CHECK((*first)->catalog_snapshot().position() == 2 && (*first)->catalog_snapshot().entries_size() == 1 && !(*first)->catalog_snapshot().complete());
    stream.dispatched();
    CHECK(stream.sent() == 0 && !stream.acknowledge(2));
    CHECK(state.publish({"routes", "three"}, "third", bytes("new"), 8, 1000));
    const auto second = stream.prepare();
    CHECK(second && *second && (*second)->catalog_snapshot().position() == 2 && (*second)->catalog_snapshot().complete());
    CHECK((*second)->catalog_snapshot().entries_size() == 1 && (*second)->catalog_snapshot().entries(0).key() != "third");
    stream.dispatched();
    CHECK(stream.sent() == 2 && stream.acknowledge(2));
    CHECK(stream.prepare().value()->catalog_snapshot().position() == 3); // With new history disabled too, recapture a baseline rather than pretending to have baseline two.

    // Expired Catalog snapshots carry positive watermarks, distinct from deletion/empty values.
    now = 5s;
    state.tick();
    astra::Dispatch<Catalog> expired(state);
    CHECK(expired.resume(0));
    const auto empty = expired.prepare();
    CHECK(empty && *empty && (*empty)->catalog_snapshot().complete());
    CHECK((*empty)->catalog_snapshot().entries_size() == 3);
    for (const auto& entry : (*empty)->catalog_snapshot().entries()) {
        CHECK(entry.record().has_watermark() && !entry.record().has_value());
        CHECK(Parcel::record(entry.record())->version > 0);
    }
}

/// Ephemeris Data/Renew use lightweight branches without repeated large Attr transmission.
void ephemeris() {

    auto now = 1000ms;
    Ephemeris::State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    const Scope scope{"services", "main"};
    const auto created = state.create(scope, bytes(std::string(65536, 'a')), bytes("old"), 1000);
    CHECK(created);
    CHECK(state.update(scope, created->uuid, bytes("new"), 10));
    CHECK(state.renew(scope, created->uuid, 20));
    CHECK(state.remove(scope, created->uuid));
    astra::Dispatch<Ephemeris> stream(state);
    CHECK(stream.resume(0));
    const auto prepared = stream.prepare();
    CHECK(prepared && *prepared && Parcel::valid((*prepared)->ephemeris_changes()));
    const auto packet = stream.dispatched();
    const auto& entries = packet.ephemeris_changes().entries();
    CHECK(entries.size() == 4 && entries[0].has_record() && entries[0].record().attr().size() == 65536);
    CHECK(entries[1].has_data() && entries[1].data().order() == 10 && entries[1].ByteSizeLong() < 128);
    CHECK(entries[2].has_lease() && entries[2].lease().order() == 20 && entries[2].ByteSizeLong() < 128);
    CHECK(entries[3].has_erase() && stream.sent() == 4);

    // Decode original absolute deadlines without adding TTL; final installation determines expiration.
    const auto decoded = Parcel::record(entries[0].record());
    CHECK(decoded && decoded->deadline == Clock::Time(2s) && decoded->ttl == 1000);
    CHECK(decoded->attr->size() == 65536 && decoded->update == 0 && decoded->renewal == 0);
}

/// Reject message/record/time limits without unsigned-to-signed wraparound or missing-oneof fallback.
void boundaries() {

    proto::astra::v1::CatalogRecord catalog;
    catalog.set_version(1);
    CHECK(!Parcel::record(catalog));
    catalog.mutable_watermark();
    CHECK(Parcel::record(catalog) && !Parcel::record(catalog)->value);
    catalog.mutable_value()->set_deadline(UINT64_MAX);
    CHECK(!Parcel::record(catalog));
    catalog.mutable_value()->set_deadline(1);
    CHECK(Parcel::record(catalog)->value && Parcel::record(catalog)->value->empty());
    catalog.mutable_value()->set_value(std::string(1024 * 1024 + 1, 'x'));
    CHECK(!Parcel::record(catalog));
    CHECK(!Parcel::time(0) && !Parcel::time(UINT64_MAX) && Parcel::time(INT64_MAX));
    proto::astra::v1::CatalogChanges changes;
    changes.set_head(3);
    for (const auto position : {1U, 3U}) {
        auto* entry = changes.add_entries();
        entry->set_position(position);
        Parcel::scope(*entry->mutable_scope(), {"routes", "main"});
        entry->set_key("key");
        entry->mutable_record()->set_version(position);
        entry->mutable_record()->mutable_watermark();
    }
    CHECK(!Parcel::valid(changes));
    changes.mutable_entries(1)->set_position(2);
    CHECK(Parcel::valid(changes));
    changes.mutable_entries(1)->set_key(std::string("k\0x", 3));
    CHECK(!Parcel::valid(changes));

    auto now = 1000ms;
    Catalog::State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
    CHECK(state.publish({"routes", "main"}, "key", bytes(std::string(4096, 'x')), 1, 1000));
    astra::Dispatch<Catalog> small(state, 256, 256);
    CHECK(!small.resume(0)); // Native-reference budgets bound preparation independently of network flow control.
    CHECK(small.sent() == 0 && small.acknowledged() == 0);
}

/// Full-source candidates span Scopes and transfer only after completeness. Bad/duplicate/position-changing pages preserve installed source.
void landing() {

    using Source = astra::Origin<Catalog::Record>;
    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, [](const Catalog::Record& value) noexcept { return value.value ? value.value->size() : 0; }, false);
    astra::Landing<Catalog> receiver(source);
    proto::astra::v1::CatalogSnapshot page;
    page.set_position(5);
    auto* entry = page.add_entries();
    Parcel::scope(*entry->mutable_scope(), {"routes", "one"});
    entry->set_key("key");
    Parcel::record(*entry->mutable_record(), Catalog::Record{20, bytes("body"), Clock::Time(2s)});
    CHECK(receiver.append(page, 0) && !receiver.complete());
    {
        const std::lock_guard lock(*gate);
        CHECK(source.position() == 0 && source.capture().size() == 0);
    }
    CHECK(!receiver.append(page, 0)); // Cross-page duplicate keys discard the whole candidate instead of last-value overwrite.
    CHECK(!receiver.complete() && receiver.position() == 0);
    CHECK(receiver.append(page, 0));
    page.clear_entries();
    page.set_complete(true);
    CHECK(receiver.append(page, 0) && receiver.complete());
    CHECK(!receiver.take(6)); // Recheck higher coverage learned after collection before final handoff.
    CHECK(source.position() == 0);
    CHECK(receiver.append(page, 0)); // An empty baseline is explicit replacement and may retain position five.
    auto candidate = receiver.take(0);
    CHECK(candidate);
    std::optional<Source::Replaced> retired;
    {
        const std::lock_guard lock(*gate);
        auto installed = source.reset(std::move(*candidate));
        CHECK(installed);
        retired.emplace(std::move(*installed));
        CHECK(source.position() == 5 && source.capture().size() == 0);
    }

    // Old baselines, nonempty position zero, and excess budget cannot advance source position or damage the valid installed empty baseline.
    page.set_position(4);
    CHECK(!receiver.append(page, 5));
    page.set_position(0);
    entry = page.add_entries();
    Parcel::scope(*entry->mutable_scope(), {"routes", "one"});
    entry->set_key("key");
    Parcel::record(*entry->mutable_record(), Catalog::Record{20, {}, {}});
    CHECK(!receiver.append(page, 0));
    page.set_position(6);
    astra::Landing<Catalog> tiny(source, 1);
    CHECK(!tiny.append(page, 5) && !tiny.complete());
    CHECK(source.position() == 5);
}
} // namespace

int main() {
    try {
        catalog();
        baseline();
        ephemeris();
        boundaries();
        records();
        events();
        frames<proto::astra::v1::CatalogChanges>();
        frames<proto::astra::v1::EphemerisChanges>();
        landing();
        std::cout << "source delivery: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
