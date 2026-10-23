// Expose the native Ephemeris domain and its lifetime-bound publication operations.
#pragma once
#include <astra/clock.hpp>
#include <astra/scope.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace astra {
/// Native Ephemeris rules. Index owns UUID; source group supplies identity/Scope without duplicating strings in records.
/// Returns unpublished candidates without source positions or notifications. Caller prepares index/history/projection before one noexcept commit.
class Ephemeris {
public:
    /// Native source/TTL/projection composition, defined in ephemeris_state.hpp without gRPC types.
    class State;
    /// Public gRPC adapter lives in ephemeris_service.hpp; native headers exclude generated/network types.
    class Service;
    /// Frozen public registration view/increments; Watch cursor advances only after completion.
    class Edition;
    /// Active downstream tasks and bounded suffixes, pumped by Runtime's shared loop without per-Watch threads.
    class Feed;
    /// Opaque Attr/Data bytes. Empty buffers are valid; null pointers are invalid missing payloads.
    using Buffer = std::vector<std::uint8_t>;
    /// Payloads must be truly immutable, without caller-owned writable aliases.
    using Value = std::shared_ptr<const Buffer>;

    /// RPC maps native errors without secrets or falsely marking uncommitted work successful.
    enum class Error {
        /// TTL/order/payload violates the static contract.
        Input,
        /// No usable local time, distinct from temporary Pulsar disconnection.
        Clock,
        /// UUID passed its finite deadline; update/renew cannot revive it.
        Ended,
        /// Operation order is below this UUID's latest order of the same type.
        Obsolete,
        /// Same Data order reused with different content.
        Conflict,
        /// Finite deadline addition overflow; never converted into a permanent lease.
        Exhausted
    };

    /// Active source record with separate Attr/Data and one finite deadline.
    struct Record {
        /// Immutable attributes fixed at Create; always nonnull for valid records.
        Value attr;
        /// Current complete Data; even empty bytes retain a nonnull pointer.
        Value data;
        /// Unix nanosecond deadline; large values remain finite and independent of client wall clocks.
        Clock::Time deadline{};
        /// Latest confirmed Data order, initially zero. New orders are positive and may skip.
        std::uint64_t update{};
        /// Latest confirmed Renew order, initially zero and independent of Data updates.
        std::uint64_t renewal{};
        /// Fixed Create TTL in milliseconds, 1000..600000; later Renew cannot change it.
        std::uint32_t ttl{};
        /// Registration generation, independent of Data order; zero only for legacy random registration.
        std::uint64_t generation{};
    };

    /// Native candidate and visibility are separate. A new same-value Data order is a source fact without advancing Observer content cursor.
    struct Change {
        /// Prepared complete record; original remains unchanged until commit.
        Record record;
        /// True for a new source fact; false for idempotent current-order confirmation, without advancing source version again.
        bool changed{};
        /// True only for content projection/observer changes; Renew always yields false.
        bool visible{};
    };

    /// Allocation-free validation of raw 16-byte UUIDv4 version/variant bits. Text aliases and invalid UUID-as-whole-Scope are rejected.
    static bool valid(std::string_view uuid) noexcept;
    /// Complete facts from one source must preserve fixed attributes and independent monotonic orders.
    static bool follows(const Record& previous, const Record& incoming) noexcept;
    /// Random 32-byte recovery capability, held only by the initial reply and SDK; never replicated downstream.
    static std::string capability();
    /// Binds capability to fixed Scope/Attr/TTL so it cannot claim another logical ID.
    static std::string identity(const Scope& scope, const Value& attr, std::uint32_t ttl, std::string_view capability);
    /// Legacy registration uses reliable randomness with fixed version/variant bits; no pseudorandom fallback.
    static std::string uuid();
    /// Validates/prepares a complete registration, sharing Attr/Data ownership. Read time under final commit protection.
    static std::expected<Record, Error> create(Value attr, Value data, std::uint32_t ttl, const Clock::Reading& reading) noexcept;
    /// A new Data order replaces all Data and extends fixed TTL without changing Attr. Equal-order/equal-body confirms only; stale or conflicting orders fail.
    static std::expected<Change, Error> update(const Record& current, Value data, std::uint64_t order, const Clock::Reading& reading) noexcept;
    /// Only a new Renew order extends fixed TTL. Orders are independent; expiration takes precedence over replay confirmation.
    static std::expected<Change, Error> renew(const Record& current, std::uint64_t order, const Clock::Reading& reading) noexcept;
    /// Final acceptance checks local time and deadline without waiting for physical cleanup; does not replace source-instance/Session validation.
    static std::expected<void, Error> active(const Record& current, const Clock::Reading& reading) noexcept;

private:
    /// Public paging policy; this domain alone defines Attr-baseline rules.
    class Encoding;
    /// Validates a complete native record with payloads, for decoded source snapshots/internal candidates only.
    static bool valid(const Record& record) noexcept;
    /// Checks nonnull shared payloads and the 1 MiB body limit without copying bytes.
    static bool valid(const Value& value) noexcept;
    /// Maps Clock deadline errors while preserving the ready/synchronized distinction.
    static Error error(Clock::Error value) noexcept;
};
} // namespace astra
