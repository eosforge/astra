// Encode native domain records into replication and public client protocol messages.
#include "parcel.hpp"

#include <astra/profile.hpp>

#include <limits>
#include <memory>
#include <stdexcept>
#include <string>

namespace astra {
bool Parcel::valid(const proto::astra::v1::Scope& message) noexcept {
    return Scope::text(message.sector(), 128) && Scope::text(message.spectrum(), 128);
}

std::optional<Scope> Parcel::scope(const proto::astra::v1::Scope& message) {
    return valid(message) ? std::optional<Scope>(Scope{message.sector(), message.spectrum()}) : std::nullopt;
}

void Parcel::scope(proto::astra::v1::Scope& message, const Scope& value) {
    message.set_allocated_sector(new std::string(value.sector));
    message.set_allocated_spectrum(new std::string(value.spectrum));
}

std::optional<Clock::Time> Parcel::time(std::uint64_t value) noexcept {
    return value != 0 && value <= static_cast<std::uint64_t>(INT64_MAX) ? std::optional<Clock::Time>(Clock::Time(std::chrono::nanoseconds(value))) : std::nullopt;
}

Catalog::Value Parcel::value(const std::string& bytes) {
    return std::make_shared<const Catalog::Buffer>(bytes.begin(), bytes.end());
}

bool Parcel::valid(const proto::astra::v1::CatalogRecord& message) noexcept {
    return message.version() != 0 && (message.has_watermark() || (message.has_value() && message.value().value().size() <= 1024 * 1024 && time(message.value().deadline())));
}

bool Parcel::valid(const proto::astra::v1::EphemerisRecord& message) noexcept {
    return message.attr().size() <= 1024 * 1024 && message.data().size() <= 1024 * 1024 && message.ttl_ms() >= 1000 && message.ttl_ms() <= 600000 && time(message.deadline()).has_value();
}

void Parcel::record(proto::astra::v1::CatalogRecord& message, const Catalog::Record& value) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.record");

    if (!Catalog::valid(value)) {
        throw std::logic_error("Invalid native Catalog record");
    }
    message.Clear(); // Assign completely each time, clearing old oneof/future optional fields in reused messages.
    message.set_version(value.version);
    if (value.value) {
        auto body = std::make_unique<proto::astra::v1::CatalogValue>(); // Own all allocating fields before publishing the oneof tag.
        body->set_allocated_value(new std::string(value.value->begin(), value.value->end()));
        body->set_deadline(static_cast<std::uint64_t>(value.deadline->time_since_epoch().count()));
        message.set_allocated_value(body.release());
    } else {
        message.set_allocated_watermark(new proto::astra::v1::Empty);
    }
}

std::optional<Catalog::Record> Parcel::record(const proto::astra::v1::CatalogRecord& message) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.record");

    if (!valid(message)) {
        return std::nullopt;
    }
    return message.has_watermark() ? Catalog::Record{message.version(), {}, {}} : Catalog::Record{message.version(), value(message.value().value()), time(message.value().deadline())};
}

void Parcel::record(proto::astra::v1::EphemerisRecord& message, const Ephemeris::Record& value) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.record");

    if (!value.attr || !value.data || value.attr->size() > 1024 * 1024 || value.data->size() > 1024 * 1024 || value.ttl < 1000 || value.ttl > 600000 || value.deadline.time_since_epoch().count() <= 0) {
        throw std::logic_error("Invalid native Ephemeris record");
    }
    message.Clear();
    message.set_allocated_attr(new std::string(value.attr->begin(), value.attr->end()));
    message.set_allocated_data(new std::string(value.data->begin(), value.data->end()));
    message.set_deadline(static_cast<std::uint64_t>(value.deadline.time_since_epoch().count()));
    message.set_update(value.update);
    message.set_renewal(value.renewal);
    message.set_ttl_ms(value.ttl);
    message.set_generation(value.generation);
}

std::optional<Ephemeris::Record> Parcel::record(const proto::astra::v1::EphemerisRecord& message) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.record");

    if (!valid(message)) {
        return std::nullopt;
    }
    return Ephemeris::Record{value(message.attr()), value(message.data()), *time(message.deadline()), message.update(), message.renewal(), message.ttl_ms(), message.generation()};
}

void Parcel::delta(proto::astra::v1::CatalogDelta& message, const Origin<Catalog::Record>::Event& event) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.delta");

    using Source = Origin<Catalog::Record>; // Only full publications and renewals enter Catalog source broadcasts.
    if (!event.name || !event.name->scope || !event.name->scope->valid() || !Scope::text(event.name->key, 1024) || event.position == 0 || !event.record || !Catalog::valid(*event.record)) {
        throw std::logic_error("Invalid Catalog source event");
    }
    message.Clear();
    message.set_position(event.position);
    // Complete the nested scope before transferring its ownership.
    auto address = std::make_unique<proto::astra::v1::Scope>();
    scope(*address, *event.name->scope);
    message.set_allocated_scope(address.release());
    message.set_allocated_key(new std::string(event.name->key));
    if (event.form == Source::Form::Renew && event.record->deadline) {
        auto lease = std::make_unique<proto::astra::v1::CatalogLease>();
        lease->set_version(event.record->version);
        lease->set_deadline(static_cast<std::uint64_t>(event.record->deadline->time_since_epoch().count()));
        message.set_allocated_lease(lease.release());
    } else if (event.form == Source::Form::Record) {
        auto row = std::make_unique<proto::astra::v1::CatalogRecord>();
        record(*row, *event.record);
        message.set_allocated_record(row.release());
    } else {
        throw std::logic_error("Catalog source has an unsupported operation");
    }
}

void Parcel::delta(proto::astra::v1::EphemerisDelta& message, const Origin<Ephemeris::Record, true>::Event& event) {

    ASTRA_PROFILE_SCOPE("star.parcel.Parcel.delta");

    using Source = Origin<Ephemeris::Record, true>; // Encode only native fields changed by the event form.
    if (!event.name || !event.name->scope || !event.name->scope->valid() || !Ephemeris::valid(event.name->key) || event.position == 0 || (event.form == Source::Form::Erase) != !event.record) {
        throw std::logic_error("Invalid Ephemeris source event");
    }
    message.Clear();
    message.set_position(event.position);
    // Complete the nested scope before transferring its ownership.
    auto address = std::make_unique<proto::astra::v1::Scope>();
    scope(*address, *event.name->scope);
    message.set_allocated_scope(address.release());
    message.set_allocated_uuid(new std::string(event.name->key));
    switch (event.form) {
    case Source::Form::Record: {
        auto row = std::make_unique<proto::astra::v1::EphemerisRecord>();
        record(*row, *event.record);
        message.set_allocated_record(row.release());
        break;
    }
    case Source::Form::Data: {
        if (!event.record->data || event.record->update == 0) {
            throw std::logic_error("Invalid Ephemeris data event");
        }
        auto body = std::make_unique<proto::astra::v1::EphemerisData>();
        body->set_allocated_data(new std::string(event.record->data->begin(), event.record->data->end()));
        body->set_order(event.record->update);
        body->set_deadline(static_cast<std::uint64_t>(event.record->deadline.time_since_epoch().count()));
        message.set_allocated_data(body.release());
        break;
    }
    case Source::Form::Renew: {
        if (event.record->renewal == 0 || event.record->deadline.time_since_epoch().count() <= 0) {
            throw std::logic_error("Invalid Ephemeris lease event");
        }
        auto lease = std::make_unique<proto::astra::v1::EphemerisLease>();
        lease->set_deadline(static_cast<std::uint64_t>(event.record->deadline.time_since_epoch().count()));
        lease->set_order(event.record->renewal);
        message.set_allocated_lease(lease.release());
        break;
    }
    case Source::Form::Erase:
        message.set_allocated_erase(new proto::astra::v1::Empty);
        break;
    }
}

bool Parcel::valid(const proto::astra::v1::CatalogChanges& message) noexcept {

    if (message.entries_size() > 256 || message.ByteSizeLong() > 8 * 1024 * 1024) {
        return false;
    }
    std::uint64_t previous{}; // First position may be any positive value; the installer checks continuity against its current prefix.
    for (const auto& entry : message.entries()) {
        if (!valid(entry.scope()) || !Scope::text(entry.key(), 1024) || entry.position() == 0 || entry.position() > message.head() || (previous && (previous == UINT64_MAX || entry.position() != previous + 1))) {
            return false;
        }
        if (!((entry.has_record() && valid(entry.record())) || (entry.has_lease() && entry.lease().version() != 0 && time(entry.lease().deadline())))) {
            return false;
        }
        previous = entry.position();
    }
    return true;
}

bool Parcel::valid(const proto::astra::v1::EphemerisChanges& message) noexcept {

    if (message.entries_size() > 256 || message.ByteSizeLong() > 8 * 1024 * 1024) {
        return false;
    }
    std::uint64_t previous{}; // Packet entries must be fully contiguous, independently of the other domain's positions.
    for (const auto& entry : message.entries()) {
        if (!valid(entry.scope()) || !Ephemeris::valid(entry.uuid()) || entry.position() == 0 || entry.position() > message.head() || (previous && (previous == UINT64_MAX || entry.position() != previous + 1))) {
            return false;
        }
        if (!((entry.has_record() && valid(entry.record())) || (entry.has_data() && entry.data().order() != 0 && entry.data().data().size() <= 1024 * 1024 && (!entry.data().deadline() || time(entry.data().deadline()))) || (entry.has_lease() && entry.lease().order() != 0 && time(entry.lease().deadline())) || entry.has_erase())) {
            return false;
        }
        previous = entry.position();
    }
    return true;
}
} // namespace astra
