// Adapt Ephemeris fields for shared snapshot and delta encoding without owning cursor state.
#pragma once
#include "ephemeris_state.hpp"
#include "pagination.hpp"

#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace astra {
/// Ephemeris public-field policy for Edition; owns no lock, cursor, or network state.
class Ephemeris::Encoding {
public:
    /// Public root and visible events for this domain.
    using Projection = State::Projection;
    /// Complete content without lease or source sequence.
    using Content = State::Content;
    /// Domain-specific wire message.
    using Reply = proto::comet::v1::EphemerisWatchReply;

    /// Allocation-free exact-target validation; the caller handles empty whole-Scope targets.
    static bool target(std::string_view value) noexcept {
        return Ephemeris::valid(value);
    }

    /// Complete point-lookup content cost; State guarantees a complete record.
    static std::size_t measure(const Content& record) noexcept {
        return record.attr->size() + record.data->size();
    }

    /// Compacts unsent events according to this domain's content/Attr baseline rules.
    static Projection::Event merge(const Projection::Event& previous, Projection::Event current) noexcept;

    /// Validates a public row and returns wire payload size; data matters only for Ephemeris increments.
    static std::size_t payload(std::string_view key, const Content* record, bool data) {
        if (!Ephemeris::valid(key) || (record && (!record->attr || !record->data))) {
            throw std::invalid_argument("Invalid Ephemeris projection record");
        }
        return record ? record->data->size() + (data ? 0 : record->attr->size()) : 0; // Data-only updates neither read nor serialize Attr.
    }

    /// Pagination already checked budget. Append only domain fields; allocation failure rolls back the whole page cursor.
    static void append(Reply& page, std::string_view key, const Content* record, bool data);
};

/// Domain-specific type sharing paging, compaction, frozen ownership, and completion cursors.
class Ephemeris::Edition : public Pagination<Encoding> {
public:
    /// Inherits whole-Scope, point, and incremental construction without a wrapper or runtime strategy.
    using Pagination<Encoding>::Pagination;
};
} // namespace astra
