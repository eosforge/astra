// CLI field annotations share option names, limits, help, and defaults with parsing.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace astra::detail {
/// Structural annotation type for public help and unsigned numeric bounds.
struct Option {
    /// Inline fixed-size text arrays satisfy constant-evaluation requirements without borrowing temporary string_view storage.
    /// Long option name without --; up to 47 bytes plus NUL, initially zero-filled.
    char name[48]{};

    /// Fixed public help text, up to 159 bytes plus NUL; never runtime data or credentials.
    char description[160]{};

    /// Inclusive numeric lower bound, default zero; not a string-length constraint.
    std::uint64_t minimum = 0;

    /// Inclusive numeric upper bound, default zero; string format and length are checked separately.
    std::uint64_t maximum = 0;

    /// Requires explicit CLI presence when true, regardless of a field initializer; defaults false.
    bool required = false;

    /// Validates and copies optionName/help at compile time; lower/upper are inclusive and mandatory controls requiredness.
    /// Oversized text fails constant evaluation; no borrowed input remains after copying.
    consteval Option(std::string_view optionName, std::string_view help, std::uint64_t lower = 0, std::uint64_t upper = 0, bool mandatory = false) : minimum(lower), maximum(upper), required(mandatory) {

        if (optionName.size() >= sizeof(name) || help.size() >= sizeof(description)) {

            throw "CLI annotation text exceeds its compile-time capacity";
        }

        // Zero-filled unused array tails supply NUL termination.

        std::ranges::copy(optionName, name);
        std::ranges::copy(help, description);
    }
};

/// Own parsed service configuration; reflection annotations define the accepted CLI contract.
struct Options {
    /// Single definition of CLI names, units, ranges, and help; default values remain field initializers.
    /// Protect only reflection-annotation declarations from formatters that do not recognize their syntax.
    // clang-format off

    /// Required Galaxy text, validated as 1..64 safe ASCII bytes.
    [[=Option{"galaxy", "Galaxy identifier: 1..64 safe ASCII bytes", 0, 0, true}]] std::string galaxy;

    /// Required numeric listener text; permits wildcard IP and OS-allocated port zero, without DNS.
    [[=Option{"listen", "Local numeric IP:PORT; wildcard requires advertise", 0, 0, true}]] std::string listen;

    /// Required Pulsar dial address; DNS name or numeric IP with nonzero port.
    [[=Option{"super", "Pulsar HOST:PORT", 0, 0, true}]] std::string pulsar;

    /// Optional reachable advertised endpoint; empty defaults to listen, explicit values require nonzero port.
    [[=Option{"advertise", "Reachable numeric IP:PORT; defaults to bound listener"}]] std::string advertise;

    /// Independent optional external listener, neither reusing internal port nor registered as a peer.
    [[=Option{"comet", "Optional public numeric IP:PORT; Star only"}]] std::string comet;
    /// Metrics listener disabled by default; use loopback locally and never advertise it as a peer.
    [[=Option{"metrics", "Optional read-only HTTP metrics IP:PORT; Star only"}]] std::string metrics;
    /// Explicit public cert.pem/key.pem directory without node-identity fallback.
    [[=Option{"comet-identity", "Public TLS certificate/key directory"}]] std::string cometIdentity;
    /// Public login defaults enabled; accepts exact lowercase true or false.
    [[=Option{"auth", "Require Comet login: true or false"}]] bool auth = true;
    /// Public TLS defaults enabled; disabling forbids a simultaneous public-certificate directory.
    [[=Option{"tls", "Protect Comet transport: true or false"}]] bool tls = true;

    /// Identity directory defaults to "identity" relative to cwd; CLI parsing handles text without file I/O.
    [[=Option{"identity", "Directory containing TLS, admission.pub and login.json"}]] std::string identity = "identity";

    /// Connection preference group, default "default", validated as 1..64 safe ASCII bytes; never an authorization scope.
    [[=Option{"group", "Preferred connection group; 1..64 safe ASCII bytes"}]] std::string group = "default";

    /// Per-role member limit, default 64, range 1..4096; Config conversion also derives inbound-RPC capacity.
    [[=Option{"max-members", "Capacity per role; Star capacity includes self", 1, 4096}]] std::uint64_t maximum = 64;

    /// Delay before the next internal Ping, default 10000 ms, range 1..86400000; zero is invalid.
    [[=Option{"heartbeat-interval-ms", "Idle delay before Ping, milliseconds", 1, 86400000}]] std::uint64_t heartbeat = 10000;

    /// Total Ping queuing/write and matching Pong budget, default 5000 ms, range 1..86400000.
    [[=Option{"pong-timeout-ms", "Ping queue/write/Pong total deadline, milliseconds", 1, 86400000}]] std::uint64_t pong = 5000;

    /// Shared graceful-shutdown budget, default 5 s, range 1..60; converted to milliseconds in Config.
    [[=Option{"shutdown-timeout-seconds", "Owned shutdown deadline, seconds", 1, 60}]] std::uint64_t shutdown = 5;

    /// Connection-status output interval, zero disables, otherwise 1..3600 s; converted to milliseconds in Config.
    [[=Option{"status-interval-seconds", "Actual-state snapshot interval; zero disables", 0, 3600}]] std::uint64_t status = 0;

    /// Pulsar admission-request cap, default 4096 bytes, range 1 byte..1 MiB.
    [[=Option{"max-admission-request-bytes", "Max admission request bytes", 1, 1024 * 1024}]] std::uint64_t maxAdmissionRequestBytes = 4 * 1024;

    /// Pulsar admission-response cap, default 2097152 bytes, range 1 KiB..256 MiB.
    [[=Option{"max-admission-response-bytes", "Max admission response bytes", 1024, 256 * 1024 * 1024}]] std::uint64_t maxAdmissionResponseBytes = 2 * 1024 * 1024;

    // clang-format on
};
} // namespace astra::detail
