// Encode native domain records into replication and public client protocol messages.
#pragma once
#include "astra.pb.h"
#include "catalog.hpp"
#include "ephemeris.hpp"
#include "origin.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace astra {
/// Bounded native-to-wire adapter. Reads no Clock, changes no source positions, and stores no second data model.
class Parcel {
public:
    /// Validates UTF-8 addresses while owning original text. Internal replication permits __ Scopes; Comet separately enforces public access.
    static std::optional<Scope> scope(const proto::astra::v1::Scope& message);
    /// Encodes validated addresses without concatenated paths or name renormalization.
    static void scope(proto::astra::v1::Scope& message, const Scope& value);
    /// Converts finite nonnegative Unix nanoseconds; overflow/zero deadlines never become infinite TTL.
    static std::optional<Clock::Time> time(std::uint64_t value) noexcept;
    /// Encodes/decodes complete Catalog bodies or explicit positive-version watermarks, preserving empty-body presence.
    static void record(proto::astra::v1::CatalogRecord& message, const Catalog::Record& value);
    /// Decode a Catalog body or watermark; invalid fields return no record and empty payload presence is retained.
    static std::optional<Catalog::Record> record(const proto::astra::v1::CatalogRecord& message);
    /// Encodes/decodes full Ephemeris records, preserving fixed Attr/TTL and independent orders.
    static void record(proto::astra::v1::EphemerisRecord& message, const Ephemeris::Record& value);
    /// Decode complete Attr, Data, TTL, and independent orders; invalid fields return no record.
    static std::optional<Ephemeris::Record> record(const proto::astra::v1::EphemerisRecord& message);
    /// Encodes native event forms without resending unrelated bodies for Renew/Data-only; invalid internal combinations throw logic errors.
    static void delta(proto::astra::v1::CatalogDelta& message, const Origin<Catalog::Record>::Event& event);
    /// Encode the Ephemeris event form, omitting unrelated bodies for renewals and data-only changes.
    static void delta(proto::astra::v1::EphemerisDelta& message, const Origin<Ephemeris::Record, true>::Event& event);
    /// Checks packet structure/hard budget only, without replacing source-identity or current-position validation.
    static bool valid(const proto::astra::v1::CatalogChanges& message) noexcept;
    /// Validate Ephemeris packet structure and its hard budget without accepting source identity or position.
    static bool valid(const proto::astra::v1::EphemerisChanges& message) noexcept;

private:
    /// Field validation only, without record construction or time reads; each Buffer is at most 1 MiB.
    static bool valid(const proto::astra::v1::CatalogRecord& message) noexcept;
    /// Validate Ephemeris fields and bounded buffers without constructing records or reading time.
    static bool valid(const proto::astra::v1::EphemerisRecord& message) noexcept;
    /// Validate sector and spectrum text for an internal replication address.
    static bool valid(const proto::astra::v1::Scope& message) noexcept;
    /// Decodes exact byte lengths, preserving NUL/empty values; caller already bounded input size.
    static Catalog::Value value(const std::string& bytes);
};
} // namespace astra
