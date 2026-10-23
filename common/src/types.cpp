// Principal encoding, stable status names, and canonical IPv4/IPv6 endpoint validation.

#include <astra/config.hpp>
#include <astra/scope.hpp>
#include <astra/types.hpp>

#include <algorithm>
#include <charconv>
#include <ranges>

// Shared SDK endpoint validation uses Winsock conversion on Windows and POSIX on Linux.
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace astra {

/// Parses strict lowercase hexadecimal Principal text into owned digest bytes, or returns an error.
Result<Principal> Principal::parse(std::string_view value) {

    // Initially zero; each validated hex pair fills a byte, with no partial digest returned on failure.
    Principal result;

    if (value.size() != result.bytes.size() * 2) {
        return Status::identity("Invalid principal length");
    }

    // Check length before parsing; reject uppercase and alternate encodings.

    for (std::size_t i = 0; i < value.size(); ++i) {
        // c is the current hex byte; i covers the complete input and only allowlisted characters are accepted.
        const auto c = value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return Status::identity("Principal must use lowercase hexadecimal");
        }

        const auto nibble = static_cast<unsigned>(c <= '9' ? c - '0' : c - 'a' + 10);
        result.bytes[i / 2] = static_cast<std::uint8_t>((static_cast<unsigned>(result.bytes[i / 2]) << 4) | nibble);
    }
    return result;
}

/// Returns the digest's owned lowercase hexadecimal encoding.
std::string Principal::text() const {

    // Lowercase hex lookup indexed by each byte's upper or lower nibble.
    constexpr std::string_view digits = "0123456789abcdef";
    // Allocates the complete 64-character output once, then fills every position.
    std::string result(bytes.size() * 2, '0');

    for (std::size_t i = 0; i < bytes.size(); ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 15];
    }
    return result;
}

/// Returns fixed allowlisted Status text for structured logging; unknown categories use internal.
std::string_view Status::name(Code code) {

    switch (code) {
    case Status::Code::Configuration:
        return "configuration";
    case Status::Code::Identity:
        return "identity";
    case Status::Code::Protocol:
        return "protocol";
    case Status::Code::Conflict:
        return "conflict";
    case Status::Code::Capacity:
        return "capacity";
    case Status::Code::Timeout:
        return "timeout";
    case Status::Code::Transport:
        return "transport";
    case Status::Code::Cancelled:
        return "cancelled";
    case Status::Code::Internal:
        return "internal";
    }
    return "internal";
}

namespace {
/// Parses a complete unsigned decimal port into uint16_t; reject signs/overflow and permit zero only for local listeners.
Result<std::uint16_t> portNumber(std::string_view value, bool local) {

    // Use a wider unsigned temporary until 16-bit and zero-port checks pass.
    unsigned port = 0;

    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);

    if (error != std::errc{} || end != value.data() + value.size() || port > 65535 || (!local && port == 0)) {
        return Status::configuration("Invalid endpoint port");
    }
    return static_cast<std::uint16_t>(port);
}
} // namespace

/// Parses numeric IP:PORT into a canonical Endpoint; local permits port zero and wildcard listeners.
Result<Endpoint> Endpoint::parse(std::string_view value, bool local) {

    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos) {
        return Status::configuration("Endpoint requires IP:PORT");
    }

    auto port = portNumber(value.substr(separator + 1), local);
    if (!port) {
        return std::unexpected(port.error());
    }

    auto host = value.substr(0, separator);

    const bool ipv6 = host.starts_with('[') && host.ends_with(']');
    if (ipv6) {
        host = host.substr(1, host.size() - 2);
    }
    std::array<unsigned char, 16> bytes{}; // Binary address storage for four-byte IPv4 or sixteen-byte IPv6.
    // family matches bracket-stripped address type and sets inet_pton/inet_ntop widths.
    const auto family = ipv6 ? AF_INET6 : AF_INET;
    // Reject embedded NUL before system numeric-address parsing.
    if (host.find('\0') != std::string_view::npos || inet_pton(family, std::string(host).c_str(), bytes.data()) != 1) {
        return Status::configuration("Endpoint requires a numeric IP without scope");
    }

    // Canonicalize identity addresses and reject IPv4-mapped IPv6 so one address cannot acquire multiple deployment digests.

    const auto count = ipv6 ? 16U : 4U;

    const bool wildcard = std::all_of(bytes.begin(), bytes.begin() + count, [](auto b) { return b == 0; });

    const bool multicast = ipv6 ? bytes[0] == 255 : (bytes[0] >= 224 && bytes[0] <= 239);

    const bool mapped = ipv6 && std::all_of(bytes.begin(), bytes.begin() + 10, [](auto b) { return b == 0; }) && bytes[10] == 255 && bytes[11] == 255;

    // Reject multicast and mapped addresses; nonlocal endpoints also reject wildcard IP.
    if (multicast || mapped || (!local && wildcard)) {
        return Status::configuration("Endpoint is not a supported unicast address");
    }

    // Re-encodes canonical numeric text before storing the endpoint.
    std::array<char, INET6_ADDRSTRLEN> normalized{};
    if (!inet_ntop(family, bytes.data(), normalized.data(), static_cast<unsigned>(normalized.size()))) {
        return Status::internal("Address normalization failed");
    }
    return Endpoint{normalized.data(), *port, ipv6, wildcard};
}

/// Returns canonical IP:PORT text with IPv6 brackets.
std::string Endpoint::text() const {
    return (ipv6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
}

/// Checks nonempty 1..64-byte ASCII names containing letters, digits, dot, underscore, or hyphen.
bool Member::validName(std::string_view value) {
    return !value.empty() && value.size() <= 64 && std::ranges::all_of(value, [](unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'; });
}

/// Checks a nonempty opaque UTF-8 ID within the 128-byte transport limit.
bool Member::validId(std::string_view id) {

    if (id.empty() || id.size() > 128) {
        return false;
    }

    // Wire bytes no longer validate UTF-8; split at NUL and reuse allocation-free text validation while preserving allowed control characters.
    // part borrows complete code-point bytes; empty segments and NUL are valid, while other bytes match Go utf8.Valid.
    return std::ranges::all_of(id | std::views::split('\0'), [](auto part) { return part.empty() || Scope::text(std::string_view(part.begin(), part.end()), 128); });
}

/// Checks Member boundaries before active-role installation; returns identity failure without changing the input.
Result<void> Member::validate() const {

    // Infrastructure role must be explicitly supported; unknown enum values never default to Star.
    if (!Member::validName(galaxy) || !Member::validName(group) || !Member::validId(id) || epoch.value == 0 || (role != Member::Role::Star && role != Member::Role::Planet && role != Member::Role::Polaris && role != Member::Role::Astrolabe)) {
        return Status::identity("Invalid member identity");
    }

    // Require canonical reachable Endpoint fields that round-trip without loss.
    auto endpoint = Endpoint::parse(address.text());
    if (!endpoint || *endpoint != address) {
        return Status::identity("Invalid canonical member endpoint");
    }
    return {};
}

/// Returns validated canonical Pulsar dial text, supporting numeric IP or DNS names with nonzero ports.
Result<std::string> Config::formatPulsar(std::string_view value) {

    if (auto endpoint = Endpoint::parse(value)) {
        return endpoint->text();
    }

    // After numeric parsing fails, validate HOSTNAME:PORT without DNS lookup.
    const auto separator = value.rfind(':');
    if (separator == std::string_view::npos || !portNumber(value.substr(separator + 1), false)) {
        return Status::configuration("Pulsar requires HOST:PORT");
    }

    // Borrows host before the final colon; validates whole-name and label lengths afterward.
    const auto host = value.substr(0, separator);
    // Identifies rejected numeric IPv4 forms so invalid addresses cannot masquerade as DNS names.
    std::array<unsigned char, 4> numeric{};

    if (inet_pton(AF_INET, std::string(host).c_str(), numeric.data()) == 1) {
        return Status::configuration("Invalid numeric Pulsar endpoint");
    }

    if (host.empty() || host.size() > 253) {
        return Status::configuration("Invalid Pulsar hostname");
    }

    // Validate each DNS label's length, characters, and nonhyphen endpoints.
    for (auto label : host | std::views::split('.')) {
        const std::string_view part(label.begin(), label.end());
        if (part.empty() || part.size() > 63 || part.starts_with('-') || part.ends_with('-') || !std::ranges::all_of(part, [](unsigned char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'; })) {
            return Status::configuration("Invalid Pulsar hostname");
        }
    }
    return std::string(value);
}

} // namespace astra
