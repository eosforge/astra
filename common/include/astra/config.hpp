// Node startup/runtime configuration and parsing contracts.
#pragma once
#include <astra/types.hpp>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace astra {

/// Node parameters and limits. Production uses Config::parse for validation; direct construction must preserve these constraints.
struct Config {
    /// Process role selected by the Star/Planet entry; defaults to star. No --role option or automatic role discovery.
    Member::Role role{};

    /// Required --galaxy: 1..64 safe ASCII bytes, matching the admission identity; empty is invalid.
    std::string galaxy;

    /// --group connection preference, default "default": 1..64 safe ASCII bytes. Planet prefers matching groups; this is not authentication.
    std::string group = "default";

    /// Required --listen numeric IP:PORT; wildcard IP and port zero for OS allocation are allowed.
    Endpoint listen;

    /// --advertise reachable endpoint, defaulting to listen. Wildcard listeners require an explicit reachable address.
    /// A defaulted zero port is replaced after bind; explicit addresses forbid zero ports and wildcard IPs.
    Endpoint advertise;

    /// Optional independent public-business listener; numeric wildcard IP and port zero allowed, excluded from internal admission.
    std::optional<Endpoint> comet;
    /// Optional HTTP /metrics listener; remote bindings require deployment network/proxy protection and do not inherit business TLS settings.
    std::optional<Endpoint> metrics;
    /// Public TLS cert.pem/key.pem directory; initially empty and required explicitly when comet and TLS are enabled.
    std::filesystem::path cometIdentity;
    /// Public-business login defaults enabled; internal node authentication and reserved __ addresses are unaffected.
    bool auth = true;
    /// Public TLS defaults enabled; internal listeners and time links remain protected independently.
    bool tls = true;

    /// Required --super Pulsar admission address: DNS name or numeric IP with nonzero port; parsing performs no network or DNS access.
    std::string pulsar;

    /// --identity directory, default "identity" relative to cwd; path length 1..4096 bytes.
    /// Runtime reads ca.pem, cert.pem, key.pem, admission.pub, and login.json here; parsing reads none of these files.
    std::filesystem::path identity = "identity";

    /// --max-members per-role capacity, default 64, range 1..4096. Star counts itself; inbound Planet members are counted separately.
    /// Does not change Planet's eight-upstream-candidate limit.
    std::size_t maxMembers = 64;

    /// Hello receive-frame limit, default 8 MiB, minimum 1024 bytes, with no CLI option.
    /// Preauthentication Hello remains capped at 4096 bytes; later data uses the smaller peer declaration, independent of queues or HTTP/2 windows.
    std::uint32_t maxFrameBytes = 8 * 1024 * 1024;

    /// Connection/TLS-readiness budget, default 3000 ms and strictly positive; capped by the total handshake deadline.
    Milliseconds connectTimeout{3000};

    /// Total connection and admission/Hello budget, default 5000 ms and strictly positive.
    /// Connection wait and Register share one attempt deadline; also bounds inbound TLS handshakes.
    Milliseconds handshakeTimeout{5000};

    /// --heartbeat-interval-ms delay after installed Hello or matching Pong before the next Ping; default 10000 ms, range 1..86400000.
    /// Zero does not disable heartbeats.
    Milliseconds heartbeatInterval{10000};

    /// --pong-timeout-ms bounds Ping queuing, network write, and matching Pong wait, as well as outgoing Pong queuing/write.
    /// Default 5000 ms, range 1..86400000; expiry closes the Session and zero is invalid.
    Milliseconds pongTimeout{5000};

    /// Initial reconnect backoff, default 100 ms; requires 0 < reconnectMin <= reconnectMax and applies on the first failure.
    Milliseconds reconnectMin{100};

    /// Maximum reconnect backoff and jitter, default 5000 ms and at least reconnectMin; also the minimum Planet candidate-refresh interval.
    Milliseconds reconnectMax{5000};

    /// Stable-session threshold from role installation, default 5000 ms and strictly positive.
    /// On disconnect, reaching this duration resets failure backoff to reconnectMin; shorter sessions retain accumulated failures.
    Milliseconds stableConnection{5000};

    /// Shared graceful-shutdown budget for admission, Sessions, and listeners; --shutdown-timeout-seconds defaults to 5, range 1..60.
    /// Stored in milliseconds (5000 by default); callbacks not drained by expiry force immediate failure exit.
    Milliseconds shutdownTimeout{5000};

    /// --status-interval-seconds connection-snapshot output interval; zero disables it, otherwise 1..3600 seconds, stored in milliseconds.
    /// Reports connection state only, not business-data readiness.
    Milliseconds statusInterval{0};

    /// Unreclaimed inbound-RPC capacity, including handshakes; default 128 and derived as maxMembers * 2 during CLI parsing.
    /// No separate CLI option; full capacity rejects admission until actual OnDone returns a slot.
    std::size_t maxInbound = 128;

    /// Concurrent outbound-attempt budget, default 4 and at least 1; installed Hello Sessions do not consume it.
    /// No CLI option; control loop starts at most one dial per round, at least 250 ms apart.
    std::size_t maxDials = 4;

    /// --max-admission-request-bytes caps outgoing Pulsar admission messages; default 4096 bytes.
    std::uint32_t maxAdmissionRequestBytes = 4 * 1024;

    /// --max-admission-response-bytes caps incoming Pulsar admission replies; default 2097152 bytes, sufficient for the maximum topology.
    std::uint32_t maxAdmissionResponseBytes = 2 * 1024 * 1024;

    /// Parses borrowed arguments (excluding executable name) into an owned Config for the entry-selected role.
    /// Reads no identity files and creates no sockets. Missing, duplicate, unknown, or out-of-range options return configuration errors.
    static Result<Config> parse(std::span<const std::string_view> arguments, Member::Role role);

    /// Returns owned plain-text help from field annotations and defaults, with no credentials, argument parsing, or filesystem access.
    /// role selects the executable name in the help text.
    static std::string help(Member::Role role);

    /// Validates a borrowed Pulsar hostname/IP and nonzero port, returning normalized dial text or a configuration error.
    /// DNS names retain original case; this performs format validation only.
    static Result<std::string> formatPulsar(std::string_view value);
};

} // namespace astra
