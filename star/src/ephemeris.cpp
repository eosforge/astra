// Expose the native Ephemeris domain and its lifetime-bound publication operations.
#include "ephemeris.hpp"

#include "random.hpp"
#include <astra/profile.hpp>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>

namespace astra {
bool Ephemeris::valid(const Value& value) noexcept {
    return value && value->size() <= 1024 * 1024;
}

bool Ephemeris::valid(const Record& record) noexcept {
    return valid(record.attr) && valid(record.data) && record.ttl >= 1000 && record.ttl <= 600000 && record.deadline.time_since_epoch().count() >= 0;
}

Ephemeris::Error Ephemeris::error(Clock::Error value) noexcept {

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

bool Ephemeris::valid(std::string_view uuid) noexcept {

    if (uuid.size() != 16) {
        return false;
    }
    const auto bytes = reinterpret_cast<const std::uint8_t*>(uuid.data());
    return (bytes[6] & 0xf0U) == 0x40U && (bytes[8] & 0xc0U) == 0x80U; // Accept only version 4 and the RFC variant, without text aliases.
}

bool Ephemeris::follows(const Record& previous, const Record& incoming) noexcept {
    return previous.ttl == incoming.ttl && *previous.attr == *incoming.attr && incoming.generation >= previous.generation && incoming.update >= previous.update && incoming.deadline >= previous.deadline && (incoming.generation > previous.generation || (incoming.renewal >= previous.renewal && (incoming.update != previous.update || incoming.renewal != previous.renewal || incoming.deadline == previous.deadline))) && (incoming.update != previous.update || *incoming.data == *previous.data);
}

std::string Ephemeris::capability() {
    std::string result(32, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), result.size()) != 1) {
        throw std::runtime_error("Ephemeris random source failed");
    }
    return result;
}

std::string Ephemeris::identity(const Scope& scope, const Value& attr, std::uint32_t ttl, std::string_view capability) {

    if (capability.size() != 32 || !attr || !scope.valid()) {
        return {};
    }
    SHA256_CTX context;
    SHA256_Init(&context);
    const auto field = [&](std::string_view value) {
        const auto size = static_cast<std::uint32_t>(value.size());
        const std::array<std::uint8_t, 4> length{static_cast<std::uint8_t>(size >> 24), static_cast<std::uint8_t>(size >> 16), static_cast<std::uint8_t>(size >> 8), static_cast<std::uint8_t>(size)};
        SHA256_Update(&context, length.data(), length.size());
        SHA256_Update(&context, value.data(), value.size());
    }; // Length-prefixed domain separation prevents concatenation collisions from changing fixed registration parameters.
    field("astra.ephemeris.capability.v1");
    field(capability);
    field(scope.sector);
    field(scope.spectrum);
    field(std::string_view(reinterpret_cast<const char*>(attr->data()), attr->size()));
    const std::array<std::uint8_t, 4> duration{static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16), static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl)};
    SHA256_Update(&context, duration.data(), duration.size());
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    SHA256_Final(digest.data(), &context);
    digest[6] = static_cast<unsigned char>((digest[6] & 0x0fU) | 0x40U);
    digest[8] = static_cast<unsigned char>((digest[8] & 0x3fU) | 0x80U);
    return std::string(reinterpret_cast<const char*>(digest.data()), 16);
}

std::string Ephemeris::uuid() {

    std::string result(16, '\0'); // Store raw binary UUID bytes without hyphenated formatting.
    random(std::span(reinterpret_cast<std::uint8_t*>(result.data()), result.size()));
    auto* bytes = reinterpret_cast<std::uint8_t*>(result.data());
    bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0fU) | 0x40U); // Set UUID version 4.
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U); // Set the RFC variant while preserving remaining random bits.
    return result;
}

std::expected<Ephemeris::Record, Ephemeris::Error> Ephemeris::create(Value attr, Value data, std::uint32_t ttl, const Clock::Reading& reading) noexcept {

    ASTRA_PROFILE_SCOPE("star.ephemeris.Ephemeris.create");

    if (!valid(attr) || !valid(data) || ttl < 1000 || ttl > 600000) {
        return std::unexpected(Error::Input);
    }
    const auto deadline = reading.deadlineAfter(std::chrono::milliseconds(ttl)); // Save one absolute deadline without reading another clock.
    if (!deadline) {
        return std::unexpected(error(deadline.error()));
    }
    return Record{std::move(attr), std::move(data), *deadline, 0, 0, ttl};
}

std::expected<void, Ephemeris::Error> Ephemeris::active(const Record& current, const Clock::Reading& reading) noexcept {

    if (!valid(current) || reading.time.time_since_epoch().count() < 0) {
        return std::unexpected(Error::Input);
    }
    if (!reading.ready) {
        return std::unexpected(Error::Clock);
    }
    if (reading.time >= current.deadline) {
        return std::unexpected(Error::Ended);
    }
    return {};
}

std::expected<Ephemeris::Change, Ephemeris::Error> Ephemeris::update(const Record& current, Value data, std::uint64_t order, const Clock::Reading& reading) noexcept {

    ASTRA_PROFILE_SCOPE("star.ephemeris.Ephemeris.update");

    if (!valid(data) || order == 0) {
        return std::unexpected(Error::Input);
    }
    if (const auto state = active(current, reading); !state) {
        return std::unexpected(state.error());
    }
    if (order < current.update) {
        return std::unexpected(Error::Obsolete);
    }
    const bool same = data == current.data || *data == *current.data; // Pointer equality avoids body comparison; never use an unreliable digest to establish equality.
    if (order == current.update) {
        return same ? std::expected<Change, Error>(Change{current, false, false}) : std::unexpected(Error::Conflict);
    }

    auto record = current; // Preserve fixed Attr, TTL, deadline, and independent renewal order without allocating payloads.
    const auto deadline = reading.deadlineAfter(std::chrono::milliseconds(current.ttl));
    if (!deadline) {
        return std::unexpected(error(deadline.error()));
    }
    record.deadline = std::max(current.deadline, *deadline);
    record.update = order;
    if (!same) {
        record.data = std::move(data);
    }
    return Change{std::move(record), true, !same};
}

std::expected<Ephemeris::Change, Ephemeris::Error> Ephemeris::renew(const Record& current, std::uint64_t order, const Clock::Reading& reading) noexcept {

    ASTRA_PROFILE_SCOPE("star.ephemeris.Ephemeris.renew");

    if (order == 0) {
        return std::unexpected(Error::Input);
    }
    if (const auto state = active(current, reading); !state) {
        return std::unexpected(state.error());
    }
    if (order < current.renewal) {
        return std::unexpected(Error::Obsolete);
    }
    if (order == current.renewal) {
        return Change{current, false, false}; // Do not recalculate deadline for replay, so valid retries at extreme values cannot report spurious addition overflow.
    }
    const auto deadline = reading.deadlineAfter(std::chrono::milliseconds(current.ttl)); // Use only the TTL fixed by Create.
    if (!deadline) {
        return std::unexpected(error(deadline.error()));
    }

    auto record = current; // Preserve Attr/Data references and Data order without payload copying.
    record.renewal = order;
    record.deadline = std::max(record.deadline, *deadline); // An anomalous earlier reading cannot shorten an already confirmed deadline.
    return Change{std::move(record), true, false};
}
} // namespace astra
