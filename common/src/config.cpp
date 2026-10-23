// Compile-time option metadata drives strict CLI parsing, validation, and owned Config construction.

#include "options.hpp"
#include <astra/config.hpp>

#include <bitset>
#include <charconv>
#include <meta>
#include <type_traits>

namespace astra {
namespace {
/// Boolean defaults come directly from field initializers and have no numeric quota.
constexpr bool validDefault(bool, const detail::Option&) {
    return true;
}

/// Checks whether numeric value lies within option's inclusive range during compile-time metadata validation.
constexpr bool validDefault(std::uint64_t value, const detail::Option& option) {
    return value >= option.minimum && value <= option.maximum;
}

/// Checks the generic 4096-byte string-default limit; requiredness and field-specific format are validated during CLI parsing.
constexpr bool validDefault(const std::string& value, const detail::Option&) {
    return value.size() <= 4096;
}

/// Compile-time field metadata; runtime parsing uses a fixed seen bitset without a dynamic registry.
// clang-format off


constexpr auto fields = std::define_static_array(std::meta::nonstatic_data_members_of(^^detail::Options, std::meta::access_context::current()));

/// Extracts exactly one Option annotation from field; wrong count or type fails constant evaluation instead of creating runtime entries.
consteval detail::Option descriptor(std::meta::info field) {

    // Compile-time annotation set must contain exactly one Option.
    auto tags = std::meta::annotations_of(field);
    if (tags.size() != 1) { throw "Each CLI field requires exactly one annotation"; }
    return std::meta::extract<detail::Option>(tags[0]);
}

/// Checks unique nonempty names, nonempty help, ordered ranges, and default bounds; false triggers static_assert.
consteval bool validDescriptors() {

    for (std::size_t i = 0; i < fields.size(); ++i) {
        // Current field's compile-time option definition for name, help, and range checks.
        auto tag = descriptor(fields[i]);

        if (tag.name[0] == '\0' || tag.description[0] == '\0' || tag.minimum > tag.maximum) { return false; }


        for (std::size_t j = 0; j < i; ++j) {
            if (std::string_view(descriptor(fields[j]).name) == tag.name) { return false; }
        }
    }

    // Field initializers provide actual defaults without a second default table.
    const detail::Options defaults;
    // Accumulates default-range validity, initially true.
    bool valid = true;



    template for (constexpr auto field : fields) {
        valid = valid && validDefault(defaults.[:field:], descriptor(field));
    }
    return valid;
}
static_assert(validDescriptors());
// clang-format on

/// Parses the complete decimal text within option's bounds, assigning output only after success.
Result<void> assign(std::uint64_t& output, std::string_view text, const detail::Option& option) {

    // Temporary decimal value is committed only after complete consumption and range validation.
    std::uint64_t value = 0;
    // end identifies unconsumed text and error reports conversion failure; both must indicate success.
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);

    if (error != std::errc{} || end != text.data() + text.size() || value < option.minimum || value > option.maximum) {
        return Status::configuration("Invalid numeric option: --" + std::string(option.name));
    }
    output = value;
    return {};
}

/// Accept exact lowercase true or false only; misspellings cannot silently disable authentication or TLS.
Result<void> assign(bool& output, std::string_view text, const detail::Option&) {
    if (text != "true" && text != "false") {
        return Status::configuration("Boolean options require true or false");
    }
    output = text == "true";
    return {};
}

/// Boolean help must not display a numeric range.
std::string defaultHelp(bool value, const detail::Option&) {
    return value ? "; default=true" : "; default=false";
}

/// Copies text into owned storage; address and name relationships are checked after all fields parse.
Result<void> assign(std::string& output, std::string_view text, const detail::Option&) {
    output = text;
    return {};
}

/// Ordinary overloads format field help; reflection enumerates fields without heterogeneous template branching.
/// Returns a string default suffix, omitted for empty defaults.
std::string defaultHelp(const std::string& value, const detail::Option&) {
    return value.empty() ? std::string{} : "; default=" + value;
}

/// Formats option's inclusive numeric range and value's default without assigning runtime arguments.
std::string defaultHelp(std::uint64_t value, const detail::Option& option) {
    return " [" + std::to_string(option.minimum) + ", " + std::to_string(option.maximum) + "]; default=" + std::to_string(value);
}
} // namespace

/// Parses argv without the executable name into a validated Config for the selected role, or returns an error.
Result<Config> Config::parse(std::span<const std::string_view> arguments, Member::Role role) {

    detail::Options options;
    std::bitset<fields.size()> seen; // Tracks which fields appeared to reject duplicate assignments.

    // Normalize --name=value and --name value before field dispatch; borrowed arguments live only for this call.
    for (std::size_t i = 0; i < arguments.size(); ++i) {
        // argument borrows the current argv entry; i tracks index and split-form options consume the next entry.
        const auto argument = arguments[i];
        if (!argument.starts_with("--")) {
            return Status::configuration("Expected a named option");
        }

        const auto separator = argument.find('=');

        const auto name = argument.substr(2, separator == std::string_view::npos ? separator : separator - 2);

        if (name == "worker-threads") {
            return Status::configuration("--worker-threads is unsupported: gRPC owns I/O workers");
        }

        // Borrowed value follows the same entry's equals sign or comes from the next argument; initially empty to detect missing values.
        std::string_view value;

        if (separator != std::string_view::npos) {
            value = argument.substr(separator + 1);
        }

        else if (i + 1 < arguments.size()) {
            value = arguments[++i];
        }

        // Reject empty values, apparent option tokens used as values, and oversized input.
        if (value.empty() || value.starts_with("--") || value.size() > 4096) {
            return Status::configuration("Missing or oversized option value");
        }

        // Initially false; set only when a declared option name matches.
        bool found = false;
        // Zero-based index aligns fields and seen; not user input.
        std::size_t index = 0;

        // Only field dispatch uses splicing; heterogeneous access expands to comparisons and assignments without virtual calls or member-pointer tables.

        // clang-format off
        template for (constexpr auto field : fields) {

            // Current field's compile-time CLI description shared by validation and help.
            constexpr auto option = descriptor(field);
            if (name == option.name) {

                if (seen.test(index)) { return Status::configuration("Duplicate option"); }

                auto result = assign(options.[:field:], value, option);
                if (!result) { return std::unexpected(result.error()); }
                seen.set(index);
                found = true;
            }
            ++index;
        }

        // clang-format on

        if (!found) {
            return Status::configuration("Unknown option");
        }
    }

    std::size_t index = 0;

    // Required-field checks use the same annotations, avoiding a second condition list.

    // clang-format off
    template for (constexpr auto field : fields) {
        if (descriptor(field).required && !seen.test(index)) { return Status::configuration("Missing required option"); }
        ++index;
    }

    // clang-format on

    // Cross-field constraints remain ordinary code rather than a metaprogramming rule engine.

    auto listen = Endpoint::parse(options.listen, true);
    // Owned validated Pulsar control-plane address, allowing valid DNS names or numeric IPs.
    auto pulsar = Config::formatPulsar(options.pulsar);
    if (!listen || !pulsar || !Member::validName(options.galaxy) || !Member::validName(options.group) || options.identity.empty()) {
        return Status::configuration("Invalid endpoint, name or identity path");
    }

    // Advertised address defaults to listen but must be reachable rather than wildcard.
    auto advertise = options.advertise.empty() ? listen : Endpoint::parse(options.advertise);

    if (!advertise || (listen->wildcard && options.advertise.empty())) {
        return Status::configuration("A concrete advertise endpoint is required");
    }

    // Construct runtime Config only after all checks; derive inbound capacity and convert CLI seconds to milliseconds.
    Config result;
    if (!options.comet.empty()) {
        if (role != Member::Role::Star) {
            return Status::configuration("Comet listening is available only on Star");
        }
        auto endpoint = Endpoint::parse(options.comet, true); // Public port binds separately; wildcard or zero endpoints never enter the node directory.
        if (!endpoint || (endpoint->port != 0 && endpoint->text() == listen->text())) {
            return Status::configuration("Invalid or conflicting public listener");
        }
        if (options.tls == options.cometIdentity.empty()) {
            return Status::configuration("Public TLS requires its own identity directory; plaintext must omit it");
        }
        result.comet = std::move(*endpoint);
    } else if (!options.cometIdentity.empty() || !options.auth || !options.tls) {
        return Status::configuration("Public transport options require --comet");
    }
    if (!options.metrics.empty()) {
        auto endpoint = Endpoint::parse(options.metrics, true); // Validates a numeric bind endpoint, permitting port zero without DNS.
        if (role != Member::Role::Star || !endpoint || (endpoint->port != 0 && (endpoint->text() == listen->text() || (result.comet && *endpoint == *result.comet)))) {
            return Status::configuration("Invalid or conflicting metrics listener");
        }
        result.metrics = std::move(*endpoint);
    }
    result.cometIdentity = std::move(options.cometIdentity);
    result.auth = options.auth;
    result.tls = options.tls;
    result.role = role;
    result.galaxy = std::move(options.galaxy);
    result.group = std::move(options.group);
    result.listen = std::move(*listen);
    result.advertise = std::move(*advertise);
    result.pulsar = std::move(*pulsar);
    result.identity = std::move(options.identity);

    result.maxMembers = options.maximum;
    result.maxInbound = options.maximum * 2;

    result.heartbeatInterval = Milliseconds(options.heartbeat);
    result.pongTimeout = Milliseconds(options.pong);
    result.shutdownTimeout = std::chrono::seconds(options.shutdown);
    result.statusInterval = std::chrono::seconds(options.status);

    result.maxAdmissionRequestBytes = static_cast<std::uint32_t>(options.maxAdmissionRequestBytes);
    result.maxAdmissionResponseBytes = static_cast<std::uint32_t>(options.maxAdmissionResponseBytes);

    return result;
}

/// Builds owned CLI help for the selected role from shared metadata and defaults.
std::string Config::help(Member::Role role) {

    // Accumulates fixed options and public defaults only.
    std::string result = "Usage: " + std::string(role == Member::Role::Star ? "star" : "planet") + " --listen=IP:PORT --super=HOST:PORT --galaxy=ID [options]\n";

    const detail::Options defaults;

    // Read defaults from the same field initializers so instances and help cannot drift.

    // clang-format off
    template for (constexpr auto field : fields) {


        constexpr auto option = descriptor(field);
        result += "  --" + std::string(option.name) + "  " + std::string(option.description);
        result += defaultHelp(defaults.[:field:], option);
        result += option.required ? " (required)\n" : "\n";
    }

    // clang-format on
    // Append the suffix in place and return by move/elision without copying the full help text.
    result += "  --help / --version\nTLS and Pulsar account login are required. Stop with SIGINT or SIGTERM.\n";
    return result;
}
} // namespace astra
