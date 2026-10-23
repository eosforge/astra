// Prepare bounded snapshot and delta protocol pages for downstream delivery.
#pragma once
#include "catalog_state.hpp"
#include "ephemeris_state.hpp"
#include "parcel.hpp"
#include <astra/profile.hpp>

#include <algorithm>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace astra {
/// One send domain on a verified peer stream. Retains a position, at most one encoded packet, and one complete baseline root, without a second business FIFO.
/// Serialized by the stream's control loop. Domain permits only the two dynamic domains; Almanac follows separate rules.
template <typename Domain>
requires(std::same_as<Domain, Catalog> || std::same_as<Domain, Ephemeris>)
class Dispatch {
public:
    /// Borrows the real committer, which must outlive this sender.
    using State = typename Domain::State;
    /// Reads only local-source facts, never relaying remote sources.
    using Source = typename State::Source;
    /// Passed directly to the existing bidirectional stream, without another byte-frame layer.
    using Packet = proto::astra::v1::SessionPacket;
    /// Retains history/clock/capacity errors for stream termination decisions.
    using Error = typename State::Error;

    /// Reserves global workspace only while retaining a frozen root.
    using Reserve = bool (*)(void*, std::size_t) noexcept;
    /// Symmetric release without user code or network operations.
    using Release = void (*)(void*, std::size_t) noexcept;

    /// Capacity is the negotiated message hard limit; target is the packing goal. Reserve at least 64 bytes for the envelope.
    explicit Dispatch(State& state, std::size_t capacity = 8 * 1024 * 1024, std::size_t target = 256 * 1024, void* context = nullptr, Reserve reserve = nullptr, Release release = nullptr) : state_(state), capacity_(capacity), target_(target), context_(context), reserve_(reserve), release_(release) {
        if (capacity < 64 || capacity > 8 * 1024 * 1024 || target == 0 || target > capacity || static_cast<bool>(reserve) != static_cast<bool>(release)) {
            throw std::invalid_argument("Invalid peer delivery limits");
        }
    }

    /// Disconnection releases frozen roots and their global budget.
    ~Dispatch() {
        baseline_.reset();
        if (release_) {
            release_(context_, retained_);
        }
    }

    /// One sender owns each root reservation; active send responsibility is neither copied nor moved.
    Dispatch(const Dispatch&) = delete;
    /// Keep one owner of replication cursor and in-flight packet; copying is forbidden.
    Dispatch& operator=(const Dispatch&) = delete;

    /// Starts after the peer's initial contiguous prefix. A stream cannot reset its send position again or regress ACK.
    std::expected<void, Error> resume(std::uint64_t position) {

        if (opened_) {
            return std::unexpected(Error::Input);
        }
        const auto delivery = state_.deliver(position, 1, capacity_); // Checks against the same captured head, without treating the position check as a new write.
        if (!delivery) {
            return std::unexpected(delivery.error());
        }
        sent_ = acknowledged_ = position;
        opened_ = true;
        return {};
    }

    /// Borrows the prepared packet; null means no current tail. Only dispatched advances send position.
    /// Rechecks the actual source head so coalesced wakeups cannot lose the final commit; sending need not wait for ACK.
    std::expected<const Packet*, Error> prepare() {

        ASTRA_PROFILE_SCOPE("star.dispatch.prepare");

        if (!opened_) {
            return std::unexpected(Error::Input);
        }
        if (packet_) {
            return &*packet_;
        }
        if (!baseline_) {
            auto delivery = state_.deliver(sent_, 256, capacity_);
            if (!delivery) {
                return std::unexpected(delivery.error());
            }
            if (delivery->baseline) {
                const auto retained = delivery->baseline->bytes(); // Conservatively charge full logical references per stream without assuming captured roots always share storage.
                if (reserve_ && !reserve_(context_, retained)) {
                    return std::unexpected(Error::Capacity);
                }
                retained_ = retained;
                baseline_.emplace(std::move(*delivery->baseline));
                offset_ = 0;
            } else {
                if (!initial_ && delivery->events.empty()) {
                    return nullptr;
                }
                auto result = changes(*delivery);
                if (!result) {
                    return std::unexpected(result.error());
                }
                return &*packet_;
            }
        }
        const auto result = snapshot(); // No same-domain increments during baseline transmission; the caller still schedules the other domain fairly.
        return result ? std::expected<const Packet*, Error>(&*packet_) : std::unexpected(result.error());
    }

    /// Move out only immediately before the sole StartWrite; preparation or queuing alone is not dispatch.
    /// Session retains the returned object through OnWriteDone, even after cancellation.
    Packet dispatched() {

        ASTRA_PROFILE_SCOPE("star.dispatch.dispatched");

        if (!packet_) {
            throw std::logic_error("No prepared peer packet");
        }
        auto packet = std::move(*packet_); // Moves Protobuf ownership on the same Arena, without another per-target event log.
        packet_.reset();
        initial_ = false;
        if (baseline_) {
            offset_ = offsetNext_;
            if (offset_ == baseline_->size()) {
                sent_ = baseline_->position();
                baseline_.reset();
                if (release_) {
                    release_(context_, retained_);
                }
                retained_ = 0;
            }
        } else {
            sent_ = positionNext_;
        }
        return packet;
    }

    /// Cumulative ACK cannot regress or exceed fully dispatched boundaries. Duplicates are harmless and never generate ACK-of-ACK.
    bool acknowledge(std::uint64_t position) noexcept {

        ASTRA_PROFILE_SCOPE("star.dispatch.acknowledge");
        if (!opened_ || position < acknowledged_ || position > sent_) {
            return false;
        }
        acknowledged_ = position;
        return true;
    }

    /// Expose sent and peer-installed positions separately; dispatch does not imply completed replication.
    std::uint64_t sent() const noexcept {
        return sent_;
    }

    /// Return the last position the peer confirmed as installed, independently of the sent cursor.
    std::uint64_t acknowledged() const noexcept {
        return acknowledged_;
    }

private:
    /// Exact repeated-submessage overhead with one-byte element tags and size bounded to 8 MiB.
    static std::size_t encoded(std::size_t size) noexcept {
        return 1 + static_cast<std::size_t>(std::max(1, (std::bit_width(size) + 6) / 7)) + size;
    }

    /// Pack a bounded prefix by actual serialized size. A valid oversized-target item gets its own packet; atomic commits are neither skipped nor split.
    std::expected<void, Error> changes(const typename Source::Delivery& delivery) {

        ASTRA_PROFILE_SCOPE("star.dispatch.changes");

        Packet packet; // Do not occupy packet_ before encoding completes; failure preserves sent_ and baseline position.
        using Body = std::conditional_t<std::same_as<Domain, Catalog>, proto::astra::v1::CatalogChanges, proto::astra::v1::EphemerisChanges>;
        auto body = std::make_unique<Body>(); // Complete the body before setting the packet oneof tag.
        body->set_head(delivery.head);
        std::size_t bytes = 32; // Reserve conservative SessionPacket/header overhead and exact body cost.
        auto position = sent_;
        for (const auto& event : delivery.events) {
            auto entry = std::make_unique<std::remove_cvref_t<decltype(*body->add_entries())>>(); // Type deduction does not execute add_entries.
            Parcel::delta(*entry, event);
            const auto cost = encoded(entry->ByteSizeLong());
            if (body->entries_size() != 0 && cost > target_ - std::min(bytes, target_)) {
                break;
            }
            if (cost > capacity_ - bytes) {
                return std::unexpected(Error::Capacity);
            }
            body->mutable_entries()->AddAllocated(entry.get()); // Publish only a complete, safely owned child.
            entry.release();
            bytes += cost;
            position = event.position;
        }
        if constexpr (std::same_as<Domain, Catalog>) {
            packet.set_allocated_catalog_changes(body.release());
        } else {
            packet.set_allocated_ephemeris_changes(body.release());
        }
        if (packet.ByteSizeLong() > capacity_) {
            return std::unexpected(Error::Capacity);
        }
        packet_.emplace(std::move(packet));
        positionNext_ = position;
        return {};
    }

    /// Page an indexed stable root without rescanning prefixes; every page shares one baseline position.
    std::expected<void, Error> snapshot() {

        ASTRA_PROFILE_SCOPE("star.dispatch.snapshot");

        Packet packet;
        using Body = std::conditional_t<std::same_as<Domain, Catalog>, proto::astra::v1::CatalogSnapshot, proto::astra::v1::EphemerisSnapshot>;
        auto body = std::make_unique<Body>(); // Do not expose an incomplete union or repeated-field child.
        body->set_position(baseline_->position());
        std::size_t bytes = 32; // Reserve encoding space for baseline, complete, and outer message.
        bool exceeded{};        // Distinguish reaching the soft target from a hard limit that cannot fit one complete record.
        const auto count = baseline_->page(offset_, 256, [&](const Scope& scope, const std::string& key, const typename Domain::Record& value) {
            auto entry = std::make_unique<std::remove_cvref_t<decltype(*body->add_entries())>>();
            auto address = std::make_unique<proto::astra::v1::Scope>();
            Parcel::scope(*address, scope);
            entry->set_allocated_scope(address.release());
            if constexpr (std::same_as<Domain, Catalog>) {
                entry->set_allocated_key(new std::string(key));
            } else {
                entry->set_allocated_uuid(new std::string(key));
            }
            auto record = std::make_unique<std::remove_cvref_t<decltype(entry->record())>>();
            Parcel::record(*record, value);
            entry->set_allocated_record(record.release());
            const auto cost = encoded(entry->ByteSizeLong());
            if (body->entries_size() != 0 && cost > target_ - std::min(bytes, target_)) {
                return false;
            }
            if (cost > capacity_ - bytes) {
                exceeded = true;
                return false;
            }
            body->mutable_entries()->AddAllocated(entry.get()); // Publish only a complete, safely owned child.
            entry.release();
            bytes += cost;
            return true;
        });
        if (exceeded) {
            return std::unexpected(Error::Capacity);
        }
        body->set_complete(offset_ + count == baseline_->size());
        if constexpr (std::same_as<Domain, Catalog>) {
            packet.set_allocated_catalog_snapshot(body.release());
        } else {
            packet.set_allocated_ephemeris_snapshot(body.release());
        }
        if (packet.ByteSizeLong() > capacity_) {
            return std::unexpected(Error::Capacity);
        }
        packet_.emplace(std::move(packet));
        offsetNext_ = offset_ + count;
        return {};
    }

    /// Fixed borrowed local committer, without another worker.
    State& state_;
    /// Per-stream hard message budget, 64 bytes..8 MiB.
    const std::size_t capacity_;
    /// Soft packing target; larger valid individual bodies remain allowed.
    const std::size_t target_;
    /// At most one source root, released when baseline sending completes.
    std::optional<typename Source::View> baseline_;
    /// At most one encoded undispatched packet; failure preserves contiguous position.
    std::optional<Packet> packet_;
    /// Complete position handed to gRPC; partial baseline pages do not advance it.
    std::uint64_t sent_{};
    /// Peer's cumulative installed position, at most sent_.
    std::uint64_t acknowledged_{};
    /// Position published only after complete packet_ handoff.
    std::uint64_t positionNext_{};
    /// Baseline rows already handed off, initially zero.
    std::size_t offset_{};
    /// Prepared next-page offset; preparation failure/cancellation preserves offset_.
    std::size_t offsetNext_{};
    /// Optional Runtime global budget, outliving the sender.
    void* context_{};
    /// Reserve and release callbacks must either both exist or both be absent.
    Reserve reserve_{};
    /// Noexcept root-budget release.
    Release release_{};
    /// Logical root bytes reserved by this sender.
    std::size_t retained_{};
    /// Whether the stream's sole recovery starting point was accepted.
    bool opened_{};
    /// Initial empty/already-caught-up recovery still requires one confirmation packet.
    bool initial_ = true;
};
} // namespace astra
