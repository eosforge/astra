// Shared status, identity, endpoint, and Member value types for core components.

#pragma once

#include <array>
#include <chrono>
#include <compare>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace astra {

/// Failure status and fixed categories; std::expected represents Result success.
struct Status {
    /// Stable failure categories used by common services and transport adapters.
    enum class Code {
        /// Invalid or missing local configuration; fix configuration before starting.
        Configuration,
        /// Identity material, TLS identity, or admission verification failed; do not retry as ordinary network failure.
        Identity,
        /// Protocol version, message type, or fields violate the contract; Planet quarantines the candidate.
        Protocol,
        /// Member epoch, identity binding, or same-direction Session conflict; preserve valid current state.
        Conflict,
        /// Member, message, or queue capacity reached; retry depends on phase and role policy.
        Capacity,
        /// Monotonic connection, handshake, or heartbeat deadline exceeded; close this attempt and back off.
        Timeout,
        /// Transport disconnected or temporarily unreachable, without implying invalid identity or protocol.
        Transport,
        /// Local or remote cancellation; await asynchronous completion before freeing RPC resources.
        Cancelled,
        /// Internal resources or runtime conditions failed; report a fixed diagnostic.
        Internal
    };

    /// Failure creator must select a category explicitly; default zero is not success.
    Code code;
    /// Owned internal diagnostic, possibly empty; external logs use name()'s fixed category.
    std::string message;

    /// Creates configuration failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto configuration(std::string message) {
        return std::unexpected(Status{Code::Configuration, std::move(message)});
    }

    /// Creates identity failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto identity(std::string message) {
        return std::unexpected(Status{Code::Identity, std::move(message)});
    }

    /// Creates protocol failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto protocol(std::string message) {
        return std::unexpected(Status{Code::Protocol, std::move(message)});
    }

    /// Creates conflict failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto conflict(std::string message) {
        return std::unexpected(Status{Code::Conflict, std::move(message)});
    }

    /// Creates capacity failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto capacity(std::string message) {
        return std::unexpected(Status{Code::Capacity, std::move(message)});
    }

    /// Creates timeout failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto timeout(std::string message) {
        return std::unexpected(Status{Code::Timeout, std::move(message)});
    }

    /// Creates transport failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto transport(std::string message) {
        return std::unexpected(Status{Code::Transport, std::move(message)});
    }

    /// Creates cancellation failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto cancelled(std::string message) {
        return std::unexpected(Status{Code::Cancelled, std::move(message)});
    }

    /// Creates internal failure, taking owned message text; empty is allowed and secrets are forbidden.
    static auto internal(std::string message) {
        return std::unexpected(Status{Code::Internal, std::move(message)});
    }

    /// Returns a stable allowlisted diagnostic without remote text; unknown enum values map to internal. View outlives this object.
    static std::string_view name(Code code);
};

/// T is the success value, or void for no payload; failure owns Status without borrowing remote messages.
template <class T>
using Result = std::expected<T, Status>;

/// Local monotonic time for Sessions, backoff, and history retention; business absolute deadlines use Clock in clock.hpp.
using Steady = std::chrono::steady_clock;
/// Millisecond duration for timeout configuration.
using Milliseconds = std::chrono::milliseconds;

/// Pulsar-issued opaque global node/entity ID; compare raw text without interpreting encoding or version bits.
using Id = std::string;

/// 32-byte SHA-256 digest of account, Galaxy, and canonical endpoint; identifies deployment instances, not a process ID.
struct Principal {
    /// Digest bytes, initially all zero.
    std::array<std::uint8_t, 32> bytes{};

    /// Compares owned digest bytes without authorizing identity.
    auto operator<=>(const Principal&) const = default;

    /// Parses value as a 64-character hexadecimal view.
    static Result<Principal> parse(std::string_view value);

    /// Returns owned 64-character encoding without borrowing Protobuf or parsing buffers.
    std::string text() const;
};

/// Locally allocated Session generation, unique within one process lifetime.
struct Generation {
    /// Unsigned 64-bit Session number; initially zero.
    std::uint64_t value{};

    /// Compares this process's Session numbers, not cross-process identity order.
    auto operator<=>(const Generation&) const = default;
};

/// Canonical numeric IP and port; host excludes IPv6 brackets and text() adds them as required.
struct Endpoint {
    /// Numeric IP text, such as "127.0.0.1" or "::1".
    std::string host;
    /// Endpoint port; initially zero.
    std::uint16_t port{};
    /// Whether host is IPv6; initially false.
    bool ipv6{};
    /// Whether host is a wildcard such as 0.0.0.0 or ::; initially false.
    bool wildcard{};

    /// Compares canonical fields without DNS or reparsing.
    auto operator<=>(const Endpoint&) const = default;

    /// Parses borrowed value into an owned canonical endpoint without DNS. local defaults false; true permits wildcards and port zero.
    /// Rejects multicast, mapped IPv6, and scope aliases. Unsupported format/address returns configuration; normalization failure returns internal.
    static Result<Endpoint> parse(std::string_view value, bool local = false);

    /// Returns owned IP:PORT text with IPv6 brackets; does not revalidate manually constructed fields.
    std::string text() const;
};

/// Independent complete topology value retained by role state, without generated-message references or credentials.
struct Member {
    /// Pulsar-issued Member epoch, distinct from locally allocated Session generations to prevent misuse.
    struct Epoch {
        /// Unsigned 64-bit epoch; initially zero.
        std::uint64_t value{};

        /// Compares Member epochs only, never local Session generations.
        auto operator<=>(const Epoch&) const = default;
    };

    /// Node topology role; protocol adapters convert encodings explicitly.
    enum class Role {
        /// Core peer Star role; the value-initialized default.
        Star,
        /// Planet attaches through a selected Star upstream, outside the Star full mesh.
        Planet,
        /// Persistent Almanac authority; control synchronization only, not a peer.
        Polaris,
        /// Management and observation entry, without peer replication or business time service.
        Astrolabe
    };

    /// Member's logical Galaxy identifier.
    std::string galaxy;
    /// Globally unique Member ID in the cluster.
    Id id;
    /// Deployment identity digest.
    Principal principal;
    /// Advertised reachable endpoint.
    Endpoint address;
    /// Current Member epoch for freshness comparisons.
    Member::Epoch epoch;
    /// Infrastructure role, default star; protocol conversion must reject unknown roles instead of defaulting.
    Member::Role role{};
    /// Connection preference group for Planet upstream selection.
    std::string group;

    /// Compares all topology fields without replacing signature or role-admission checks.
    auto operator<=>(const Member&) const = default;

    /// Validates Member before shared-state installation: valid name, opaque ID, nonzero epoch, and canonical reachable endpoint required.
    /// Returns identity on failure without modifying input or verifying signatures; every caller must check the result.
    Result<void> validate() const;

    /// Validates 1..64 ASCII bytes containing only letters, digits, dot, underscore, or hyphen, matching Go/Rust rules.
    /// No Unicode or case normalization; empty or out-of-range values return false.
    static bool validName(std::string_view value);

    /// Validates a nonempty UTF-8 ID of at most 128 bytes, allowing embedded NUL/control characters; Identity verifies issuance signatures.
    static bool validId(std::string_view id);
};

} // namespace astra
