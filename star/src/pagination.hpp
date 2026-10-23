// Order and compact event pages while preserving atomic batch and memory-accounting boundaries.
#pragma once
#include "comet.pb.h"
#include <astra/profile.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace astra {
/// Shared frozen paging for dynamic domains. Encoding supplies costing, validation, field encoding, and same-name compaction.
/// Owns no mutable State, virtual dispatch, runtime domain flag, or extra body copies; network confirmation belongs to the caller.
template <typename Encoding>
class Pagination {
    /// Domain-specific immutable Scene root/events.
    using Projection = typename Encoding::Projection;
    /// Public content without TTL or source-recovery positions.
    using Content = typename Encoding::Content;
    /// Visible changes within an already verified contiguous interval.
    using Event = typename Projection::Event;

public:
    /// Separate generated message preserving static domain type checks.
    using Reply = typename Encoding::Reply;

    /// Freezes a whole Scope by sharing its index root; read version/accounting from the moved-to object.
    explicit Pagination(typename Projection::View view) : data_(std::make_shared<const Data>(std::move(view))) {
        const auto& captured = std::get<typename Projection::View>(*data_); // Root and metadata share one capture boundary.
        version_ = captured.version();
        bytes_ = captured.bytes();
    }

    /// A missing exact target forms a valid empty reset without a whole-Scope snapshot.
    Pagination(std::string key, typename Projection::Point point) : data_(std::make_shared<const Data>(Point{std::move(key), std::move(point.record)})), version_(point.version) {
        const auto& value = std::get<Point>(*data_); // Owned key; nonnull record contains complete public content.
        bytes_ = sizeof(Point) + value.key.size() + (value.record ? Encoding::measure(*value.record) : 0);
    }

    /// Changes cover through version. Filtering/compaction changes rows, never the completion cursor; invalid batches throw invalid_argument.
    Pagination(std::uint64_t version, std::vector<Event> changes, std::string_view target = {}) : mode_(proto::comet::v1::MODE_APPLY), version_(version) {

        // Validate before filtering so unrelated targets cannot hide malformed events. Data-only cannot point to deletion.
        for (const auto& change : changes) {
            if (!change.name || change.version == 0 || change.version > version || (change.data && !change.record)) {
                throw std::invalid_argument("Invalid projection change batch");
            }
        }
        if (!target.empty()) {
            std::erase_if(changes, [&](const auto& change) { return change.name->key != target; });
        }
        const auto order = [](const auto& change) { return std::tie(change.name->key, change.version); }; // Compare through references without copying names or payloads.
        if (!std::ranges::is_sorted(changes, {}, order)) {
            // Sort compact indices, then move events along permutation cycles, avoiding repeated optional-body/shared-owner moves during sorting.
            // Sorting Event directly triggered GCC Release maybe-uninitialized; preserve warnings rather than suppressing them for shorter code.
            // Ordered suffixes allocate nothing; unordered history temporarily uses one size_t per event.
            std::vector<std::size_t> positions(changes.size());
            for (std::size_t index = 0; index < positions.size(); ++index) {
                positions[index] = index;
            }
            std::ranges::sort(positions, {}, [&](std::size_t index) { return order(changes[index]); });

            // Positions map destinations to original indices; completed cycles become identity mappings, moving each item to its destination once.
            for (std::size_t first = 0; first < positions.size(); ++first) {
                if (positions[first] == first) {
                    continue;
                }
                Event saved{}; // Create an explicit empty slot before retaining the first cycle item, then fill the final hole on closure.
                saved = std::move(changes[first]);
                auto slot = first;
                while (positions[slot] != first) {
                    const auto source = positions[slot];
                    changes[slot] = std::move(changes[source]);
                    positions[slot] = slot;
                    slot = source;
                }
                changes[slot] = std::move(saved);
                positions[slot] = slot;
            }
        }

        // Compact same-name events in place using domain rules, without a new hash table.
        std::size_t kept{}; // Compacted prefix length, distinct from vector capacity.
        for (std::size_t first = 0; first < changes.size();) {
            auto& latest = changes[first]; // Use the first same-name item as the merge target without extra shared references.
            auto end = first + 1;
            while (end < changes.size() && changes[end].name->key == latest.name->key) {
                latest = merge(latest, std::move(changes[end]));
                ++end;
            }
            bytes_ += latest.bytes;
            if (kept != first) {
                changes[kept] = std::move(latest); // Avoid self-move that could lose names/bodies.
            }
            ++kept;
            first = end;
        }
        bytes_ += (changes.capacity() - kept) * sizeof(Event); // Resize retains tail capacity, which remains charged.
        changes.resize(kept);
        data_ = std::make_shared<const Data>(std::move(changes));
    }

    /// Move transfers the shared source; copies retain independent cursors without copying bodies/history containers.
    Pagination(Pagination&&) noexcept = default;
    /// Share immutable page inputs while copying this cursor position; subsequent paging advances independently.
    Pagination(const Pagination&) noexcept = default;
    /// A cache hit adopts the encoded position without implying completed network Write.
    Pagination& operator=(const Pagination&) noexcept = default;

    /// Domain validates nonempty targets; caller handles empty whole-Scope selection.
    static bool target(std::string_view value) noexcept {
        return Encoding::target(value);
    }

    /// Frozen-batch compaction: Catalog retains the final value; Ephemeris also retains evidence for full Attr.
    static Event merge(const Event& previous, Event current) noexcept {
        return Encoding::merge(previous, std::move(current));
    }

    /// Cache-match mode, never inferred from version zero.
    bool reset() const noexcept {
        return mode_ == proto::comet::v1::MODE_RESET;
    }

    /// Complete page constructed, without network acknowledgement.
    bool complete() const noexcept {
        return complete_;
    }

    /// Complete cursor captured with root/suffix, confirmed externally only after successful Write.
    std::uint64_t version() const noexcept {
        return version_;
    }

    /// Conservative batch retention charge, unchanged by page consumption; not added RSS.
    std::size_t bytes() const noexcept {
        return bytes_;
    }

    /// Soft target 256 KiB/256 rows; one larger row may occupy a page within the 8 MiB hard limit. Failure preserves cursor.
    Reply next(std::string_view instance) {

        ASTRA_PROFILE_SCOPE("star.pagination.next");

        if (complete_) {
            throw std::logic_error("Projection edition already completed");
        }
        if (instance.empty() || instance.size() > 128) {
            throw std::invalid_argument("Invalid serving instance");
        }
        Reply page; // Each page owns its message; no writable object reuse across pages.
        page.set_mode(mode_);
        std::size_t bytes = instance.size() + 64; // Reserve final identity/cursor space before encoding so the last page cannot exceed limits.
        std::size_t consumed{};                   // Successful rows on this page; exceptions preserve offset_.
        bool finished = true;                     // Empty Scopes, missing exact targets, and unrelated-only changes still send complete.

        if (const auto* view = std::get_if<typename Projection::View>(data_.get())) {
            consumed = view->page(offset_, 256, [&](const std::string& key, const Content& record) { return append(page, bytes, key, &record, false); });
            finished = offset_ + consumed == view->size();
        } else if (const auto* point = std::get_if<Point>(data_.get())) {
            if (point->record) {
                static_cast<void>(append(page, bytes, point->key, &*point->record, false));
                consumed = 1;
            }
        } else {
            const auto& changes = std::get<std::vector<Event>>(*data_); // Read only frozen content, without adding newer State records.
            while (offset_ + consumed < changes.size()) {
                const auto& change = changes[offset_ + consumed]; // Final row action and Attr-baseline hint.
                if (!append(page, bytes, change.name->key, change.record ? &*change.record : nullptr, change.data)) {
                    break;
                }
                ++consumed;
            }
            finished = offset_ + consumed == changes.size();
        }

        if (finished) {
            page.set_complete(true);
            page.set_version(version_);
            page.set_allocated_instance(new std::string(instance)); // Allocate before setting the generated presence bit.
        }
        offset_ += consumed;
        complete_ = finished;
        return page;
    }

private:
    /// Point result owns name/optional complete content. Null means missing, not a deletion increment.
    struct Point {
        /// Owned raw Catalog key or Ephemeris UUID bytes.
        std::string key;
        /// Complete captured public content, never filled from later state.
        std::optional<Content> record;
    };

    /// Domain validates/measures first, then shared budget/append logic. Soft-limit rejection does not consume the row.
    static bool append(Reply& page, std::size_t& bytes, std::string_view key, const Content* record, bool data) {

        const auto payload = Encoding::payload(key, record, data); // Reads scalar lengths without intermediate encoding allocations.
        constexpr std::size_t hard = 8 * 1024 * 1024;              // Hard page limit matching the caller's budget.
        if (key.size() > hard || payload > hard) {
            throw std::length_error("Projection record exceeds page budget");
        }
        const auto cost = key.size() + payload + 48; // Conservative nested-field/length overhead; domain payloads retain their business limits.
        if (bytes >= hard || cost > hard - bytes) {
            throw std::length_error("Projection record exceeds page budget");
        }
        if (page.changes_size() != 0 && (page.changes_size() >= 256 || cost > 256 * 1024 - std::min(bytes, std::size_t{256 * 1024}))) {
            return false;
        }
        Encoding::append(page, key, record, data);
        bytes += cost;
        return true;
    }

    /// Three fixed source forms, independent of business-domain selection.
    using Data = std::variant<typename Projection::View, Point, std::vector<Event>>;
    /// Subscribers share frozen sources with independent page positions.
    std::shared_ptr<const Data> data_;
    /// Fixed for the entire batch.
    proto::comet::v1::Mode mode_ = proto::comet::v1::MODE_RESET;
    /// Complete Scope cursor at freeze, including valid zero.
    std::uint64_t version_{};
    /// Conservative referenced bytes, initially zero.
    std::size_t bytes_{};
    /// Successfully constructed rows, initially zero.
    std::size_t offset_{};
    /// True after the last page is constructed; further next is forbidden.
    bool complete_{};
};
} // namespace astra
