// Expose the native Catalog domain and its retained business-state operations.
#include "catalog.hpp"

#include <astra/profile.hpp>

#include <algorithm>
#include <chrono>

namespace astra {
bool Catalog::valid(const Record& record) noexcept {
    return record.version != 0 && static_cast<bool>(record.value) == record.deadline.has_value() && (!record.value || (record.value->size() <= 1024 * 1024 && record.deadline->time_since_epoch().count() >= 0));
}

bool Catalog::valid(const Record* source, const Record* merged) noexcept {
    return (!source || valid(*source)) && (!merged || valid(*merged));
}

Catalog::Error Catalog::error(Clock::Error value) noexcept {

    switch (value) {
    case Clock::Error::ClockUnready:
        return Error::Clock;
    case Clock::Error::InvalidTime:
        return Error::Input;
    case Clock::Error::Exhausted:
        return Error::Exhausted;
    }
    return Error::Input;
}

std::expected<void, Catalog::Error> Catalog::ready(const Clock::Reading& reading) noexcept {

    if (reading.time.time_since_epoch().count() < 0) {
        return std::unexpected(Error::Input);
    }
    if (!reading.ready) {
        return std::unexpected(Error::Clock);
    }
    return {};
}

std::expected<void, Catalog::Error> Catalog::check(const Record* current, std::uint64_t version, const Value& value) noexcept {

    if (!current) {
        return {};
    }
    if (version < current->version) {
        return std::unexpected(Error::Version);
    }
    if (version == current->version && current->value && value != current->value && *value != *current->value) {
        return std::unexpected(Error::Conflict);
    }
    return {};
}

std::expected<Catalog::Record, Catalog::Error> Catalog::publish(const Record* source, const Record* merged, Value value, std::uint64_t version, std::uint32_t ttl, const Clock::Reading& reading) noexcept {

    ASTRA_PROFILE_SCOPE("star.catalog.Catalog.publish");

    if (!valid(source, merged) || !value || value->size() > 1024 * 1024 || version == 0 || ttl < 1000 || ttl > 600000) {
        return std::unexpected(Error::Input);
    }
    if (const auto checked = check(source, version, value); !checked) {
        return std::unexpected(checked.error());
    }
    if (const auto checked = check(merged, version, value); !checked) {
        return std::unexpected(checked.error());
    }
    const auto deadline = reading.deadlineAfter(std::chrono::milliseconds(ttl)); // Use this source's candidate deadline, never a later merged remote deadline.
    if (!deadline) {
        return std::unexpected(error(deadline.error()));
    }

    Record record{version, std::move(value), *deadline}; // A new version uses only the requested TTL, without inheriting an older deadline.
    if (source && source->version == version && source->value) {
        record.value = source->value; // Exact equality is already checked; reuse immutable bytes without duplicate content history.
        record.deadline = std::max(*source->deadline, *deadline);
    } else if (merged && merged->version == version && merged->value) {
        record.value = merged->value; // Reuse only immutable bodies, not source deadlines or identity.
    }
    return record;
}

std::expected<Catalog::Record, Catalog::Error> Catalog::renew(const Record* source, const Record* merged, std::uint64_t version, std::uint32_t ttl, const Clock::Reading& reading) noexcept {

    ASTRA_PROFILE_SCOPE("star.catalog.Catalog.renew");

    if (!valid(source, merged) || version == 0 || ttl < 1000 || ttl > 600000) {
        return std::unexpected(Error::Input);
    }
    if (const auto clock = ready(reading); !clock) {
        return std::unexpected(clock.error());
    }
    if ((merged && merged->version > version) || (source && source->version != version)) {
        return std::unexpected(Error::Version);
    }
    if (!source || !source->value || reading.time >= *source->deadline) {
        return std::unexpected(Error::Ended);
    }
    const auto deadline = reading.deadlineAfter(std::chrono::milliseconds(ttl)); // TTL is explicit; zero never means reuse the old value.
    if (!deadline) {
        return std::unexpected(error(deadline.error()));
    }

    auto record = *source; // Share ownership but keep metadata private so renewals cannot change frozen source snapshots.
    record.deadline = std::max(*record.deadline, *deadline);
    return record;
}

Catalog::Record Catalog::expire(const Record& current, Clock::Time now) noexcept {
    return current.deadline && now >= *current.deadline ? Record{current.version, nullptr, std::nullopt} : current;
}

bool Catalog::visible(const Record* current, const Record& candidate) noexcept {

    if (!current || !current->value) {
        return static_cast<bool>(candidate.value);
    }
    if (!candidate.value || current->version != candidate.version) {
        return true;
    }
    return current->value != candidate.value && *current->value != *candidate.value;
}

std::expected<Catalog::Change, Catalog::Error> Catalog::merge(const Record* current, const Record& incoming, Clock::Time now) noexcept {

    ASTRA_PROFILE_SCOPE("star.catalog.Catalog.merge");

    if (!valid(current, &incoming) || now.time_since_epoch().count() < 0) {
        return std::unexpected(Error::Input);
    }
    if (current && current->version == incoming.version && current->value && incoming.value && current->value != incoming.value && *current->value != *incoming.value) {
        return std::unexpected(Error::Conflict);
    }

    auto record = current ? expire(*current, now) : Record{}; // Local expiration changes only the downstream projection; never broadcast it as source termination.
    const auto fact = expire(incoming, now);                  // Evaluate the original source deadline without granting late messages a new TTL.
    if (!current || incoming.version > current->version) {
        record = fact; // Expired higher facts/watermarks still raise the floor, preventing fallback to a live lower version.
    } else if (incoming.version == current->version && fact.value) {
        if (!record.value) {
            record = fact;
        } else {
            record.deadline = std::max(*record.deadline, *fact.deadline); // Equal versions from multiple sources retain the longest known valid deadline.
        }
    }
    return Change{record, visible(current, record)};
}
} // namespace astra
