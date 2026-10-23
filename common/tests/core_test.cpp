// Verify shared configuration, values, and core policy behavior.
#include "check.hpp"
#include "topology.hpp"
#include "utf8.hpp"
#include <astra/config.hpp>
#include <astra/scope.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace astra;

namespace {

/// Creates deterministic test Members from n, default Star/epoch 1, with matching ID, digest, and port outside real deployments.
Member member(unsigned n, Member::Role role = Member::Role::Star, std::uint64_t epoch = 1) {

    // Owned Member result; fill every valid identity field before return.
    Member result;
    result.galaxy = "alpha";
    result.group = "default";
    result.id = "issued/" + std::to_string(1000 + n);
    result.principal.bytes[0] = static_cast<std::uint8_t>(n);
    result.address = *Endpoint::parse("127.0.0.1:" + std::to_string(7000 + n));
    result.epoch = Member::Epoch{epoch};
    result.role = role;
    return result;
}

/// Reject noncanonical or inconsistent endpoint fields before admitting any supported member role.
void canonical() {

    /// Describe a literal wire-independent endpoint and its admission result.
    struct Entry {
        /// Own the complete endpoint, including flags that text() does not expose.
        Endpoint address;
        /// Require exact canonical fields for an advertised, remotely usable endpoint.
        bool accepted;
    };

    // Expectations follow the public Endpoint/Member contracts, not parser-generated fixtures.
    const std::array entries{
        Entry{{"127.0.0.1", 1, false, false}, true},
        Entry{{"127.0.0.1", 65535, false, false}, true},
        Entry{{"::1", 7443, true, false}, true},
        Entry{{"2001:db8::1", 7443, true, false}, true},
        Entry{{"2001:0db8:0:0:0:0:0:1", 7443, true, false}, false},
        Entry{{"2001:DB8::1", 7443, true, false}, false},
        Entry{{"127.0.0.1", 7443, false, true}, false},
        Entry{{"::1", 7443, true, true}, false},
        Entry{{"127.0.0.1", 7443, true, false}, false},
        Entry{{"::1", 7443, false, false}, false},
        Entry{{"127.0.0.1", 0, false, false}, false},
        Entry{{"0.0.0.0", 7443, false, true}, false},
        Entry{{"::", 7443, true, true}, false},
        Entry{{"224.0.0.1", 7443, false, false}, false},
        Entry{{"ff02::1", 7443, true, false}, false},
        Entry{{"::ffff:127.0.0.1", 7443, true, false}, false},
        Entry{{"127.000.0.1", 7443, false, false}, false},
        Entry{{std::string("127.0.0.1") + '\0' + "ignored", 7443, false, false}, false},
        Entry{{"localhost", 7443, false, false}, false},
        Entry{{"", 7443, false, false}, false},
    };
    for (const auto role : {Member::Role::Star, Member::Role::Planet, Member::Role::Polaris, Member::Role::Astrolabe}) {
        for (std::size_t index = 0; index < entries.size(); ++index) {
            // Validation must neither normalize borrowed identity fields nor partially repair rejected input.
            auto candidate = member(1, role);
            candidate.address = entries[index].address;
            const auto before = candidate;
            const auto result = candidate.validate();
            CHECK(result.has_value() == entries[index].accepted);
            CHECK(candidate == before);
            CHECK(result || result.error().code == Status::Code::Identity);
            std::cout << "ASTRA-MEMBER {\"role\":" << static_cast<int>(role) << ",\"case\":" << index << ",\"accepted\":" << (result ? "true" : "false") << "}\n";
        }
    }
}

/// Validate the complete scalar domain and literal malformed sequences without normalizing scope bytes.
void scopes() {

    // These independent RFC 3629 vectors anchor the fixture encoder at every width and surrogate boundary.
    for (const auto& [scalar, bytes] : test::scalars) {
        CHECK(test::encoded(scalar) == bytes);
    }

    // Every non-NUL scalar is legal, including noncharacters; surrogate code points are not Unicode scalars.
    // The oracle follows RFC 3629 sections 3-4 and proto/README.md's no-NUL, raw-byte Scope contract.
    std::uint32_t effective = 0;
    for (std::uint32_t scalar = 1; scalar <= 0x10ffff; ++scalar) {
        if (scalar >= 0xd800 && scalar <= 0xdfff) {
            continue;
        }
        CHECK(Scope::text(test::encoded(scalar), 4));
        ++effective;
    }
    CHECK(effective == 1'112'063);

    for (const auto& entry : test::texts) {
        CHECK(Scope::text(entry.bytes, 128) == entry.accepted);
        CHECK((Scope{entry.bytes, "ordinary"}.valid() == entry.accepted));
        CHECK((Scope{"ordinary", entry.bytes}.valid() == entry.accepted));
        CHECK(!Scope::text(entry.bytes, 0));
        if (!entry.bytes.empty()) {
            CHECK(!Scope::text(entry.bytes, entry.bytes.size() - 1));
        }
    }

    // Byte limits apply independently to both fields, including multibyte scalars at the exact limit.
    const std::string boundary = std::string(124, 'x') + "\xf4\x8f\xbf\xbf";
    CHECK(Scope::text(boundary, 128));
    CHECK(!Scope::text(boundary, 127));
    CHECK(!Scope::text(boundary + "x", 128));
    CHECK((Scope{boundary, boundary}.valid()));
    CHECK((!Scope{boundary + "x", boundary}.valid()));
    CHECK((!Scope{boundary, boundary + "x"}.valid()));
    CHECK((!Scope{"", "ordinary"}.valid()));
    CHECK((!Scope{"ordinary", ""}.valid()));

    // Routing compares original bytes: no Unicode composition, path interpretation or permission repair.
    const Scope composed{"\xc3\xa9", "main"}, decomposed{"e\xcc\x81", "main"};
    CHECK(composed.valid() && decomposed.valid() && composed != decomposed);
    CHECK((Scope{"a", "z"} < Scope{"b", "a"}));
    CHECK((Scope{"a", "a"} < Scope{"a", "b"}));
    CHECK((Scope{"__private", "ordinary"}.internal()));
    CHECK((!Scope{"x/__private", "ordinary"}.internal()));
    CHECK((!Scope{"_private", "ordinary"}.internal()));
    CHECK((Scope{"__private", ""}.internal() && !Scope{"__private", ""}.valid()));
    std::cout << "ASTRA-VALUES {\"kind\":\"scope\",\"scalar_cases\":" << effective << ",\"literal_cases\":" << test::texts.size() << "}\n";
}

/// Verify stable diagnostic names, including enum values outside the public vocabulary.
void statuses() {

    // Literal names are the public logging contract, independent of the implementation switch.
    constexpr std::array names{"configuration", "identity", "protocol", "conflict", "capacity", "timeout", "transport", "cancelled", "internal"};
    for (std::size_t index = 0; index < names.size(); ++index) {
        CHECK(Status::name(static_cast<Status::Code>(index)) == names[index]);
    }
    for (const auto value : {-1, 9, std::numeric_limits<int>::max()}) {
        CHECK(Status::name(static_cast<Status::Code>(value)) == "internal");
    }
    std::cout << "ASTRA-VALUES {\"kind\":\"status\",\"cases\":12}\n";
}

/// Exercise each identity field independently without repairing rejected caller-owned values.
void identities() {

    // A literal alphabet tests every byte both alone and between valid characters.
    constexpr std::string_view alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
    for (unsigned value = 0; value != 256; ++value) {
        const std::string text(1, static_cast<char>(value));
        const bool accepted = alphabet.find(text) != std::string_view::npos;
        CHECK(Member::validName(text) == accepted);
        CHECK(Member::validName("a" + text + "z") == accepted);
    }

    /// Change one field of an otherwise valid member before admission.
    struct Entry {
        /// Apply a fixture-owned mutation without invoking production validation.
        void (*apply)(Member&);
        /// State whether the independent field contract admits the resulting member.
        bool accepted;
    };

    const std::array entries{
        Entry{[](Member&) {}, true},
        Entry{[](Member& value) { value.galaxy.clear(); }, false},
        Entry{[](Member& value) { value.galaxy.assign(64, 'a'); }, true},
        Entry{[](Member& value) { value.galaxy.assign(65, 'a'); }, false},
        Entry{[](Member& value) { value.galaxy = "alpha/beta"; }, false},
        Entry{[](Member& value) { value.group.clear(); }, false},
        Entry{[](Member& value) { value.group.assign(64, 'Z'); }, true},
        Entry{[](Member& value) { value.group.assign(65, 'Z'); }, false},
        Entry{[](Member& value) { value.group = "group name"; }, false},
        Entry{[](Member& value) { value.id.clear(); }, false},
        Entry{[](Member& value) { value.id.assign(128, 'x'); }, true},
        Entry{[](Member& value) { value.id.assign(129, 'x'); }, false},
        Entry{[](Member& value) { value.id = std::string("a\0b", 3); }, true},
        Entry{[](Member& value) { value.id = "\xf4\x8f\xbf\xbf"; }, true},
        Entry{[](Member& value) { value.id = "\xed\xa0\x80"; }, false},
        Entry{[](Member& value) { value.id = "\xf0\x90\x80"; }, false},
        Entry{[](Member& value) { value.epoch.value = 0; }, false},
        Entry{[](Member& value) { value.epoch.value = std::numeric_limits<std::uint64_t>::max(); }, true},
        Entry{[](Member& value) { value.role = static_cast<Member::Role>(-1); }, false},
        Entry{[](Member& value) { value.role = static_cast<Member::Role>(4); }, false},
    };
    for (const auto role : {Member::Role::Star, Member::Role::Planet, Member::Role::Polaris, Member::Role::Astrolabe}) {
        for (std::size_t index = 0; index < entries.size(); ++index) {
            auto candidate = member(1, role);
            entries[index].apply(candidate);
            const auto before = candidate;
            const auto result = candidate.validate();
            CHECK(result.has_value() == entries[index].accepted);
            CHECK(candidate == before);
            CHECK(result || result.error().code == Status::Code::Identity);
            std::cout << "ASTRA-IDENTITY {\"role\":" << static_cast<int>(role) << ",\"case\":" << index << ",\"accepted\":" << (result ? "true" : "false") << "}\n";
        }
    }
    std::cout << "ASTRA-VALUES {\"kind\":\"identity\",\"cases\":592}\n";
}

/// Check numeric and DNS address boundaries using literal normalized results.
void addresses() {

    /// Describe one numeric address independently of the production parser.
    struct Entry {
        /// Own the exact input bytes, including any embedded NUL.
        std::string input;
        /// Permit listener-only wildcard and zero-port behavior when true.
        bool local;
        /// Require every normalized field, or a configuration error when absent.
        std::optional<Endpoint> expected;
    };

    const std::array entries{
        Entry{"127.0.0.1:1", false, Endpoint{"127.0.0.1", 1, false, false}},
        Entry{"127.0.0.1:65535", false, Endpoint{"127.0.0.1", 65535, false, false}},
        Entry{"[2001:0DB8:0:0:0:0:0:1]:7443", false, Endpoint{"2001:db8::1", 7443, true, false}},
        Entry{"0.0.0.0:0", true, Endpoint{"0.0.0.0", 0, false, true}},
        Entry{"[::]:0", true, Endpoint{"::", 0, true, true}},
        Entry{"127.0.0.1:0", true, Endpoint{"127.0.0.1", 0, false, false}},
        Entry{"", false, std::nullopt},
        Entry{"127.0.0.1", false, std::nullopt},
        Entry{"127.0.0.1:", false, std::nullopt},
        Entry{"127.0.0.1:0", false, std::nullopt},
        Entry{"127.0.0.1:65536", false, std::nullopt},
        Entry{"127.0.0.1:4294967296", false, std::nullopt},
        Entry{"127.0.0.1:-1", false, std::nullopt},
        Entry{"127.0.0.1:+1", false, std::nullopt},
        Entry{"127.0.0.1:1x", false, std::nullopt},
        Entry{"127.0.0.1: 1", false, std::nullopt},
        Entry{"localhost:1", false, std::nullopt},
        Entry{"[fe80::1%2]:1", false, std::nullopt},
        Entry{"[::ffff:127.0.0.1]:1", true, std::nullopt},
        Entry{"224.0.0.1:1", true, std::nullopt},
        Entry{"[ff02::1]:1", true, std::nullopt},
        Entry{std::string("127.0.0.1") + '\0' + ":1", false, std::nullopt},
    };
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        const auto before = entry.input;
        const auto result = Endpoint::parse(entry.input, entry.local);
        CHECK(result.has_value() == entry.expected.has_value());
        CHECK(result ? *result == *entry.expected : result.error().code == Status::Code::Configuration);
        CHECK(entry.input == before);
        std::cout << "ASTRA-ADDRESS {\"kind\":\"numeric\",\"case\":" << index << ",\"accepted\":" << (result ? "true" : "false") << "}\n";
    }

    // Empty expected output means rejection; successful hostname spelling stays caller-owned.
    const std::string label(63, 'a');
    const auto maximum = label + "." + label + "." + label + "." + std::string(61, 'b');
    const std::array names{
        std::pair<std::string, std::string>{"127.0.0.1:7444", "127.0.0.1:7444"},
        std::pair<std::string, std::string>{"[2001:0DB8::1]:7444", "[2001:db8::1]:7444"},
        std::pair<std::string, std::string>{"Pulsar.EXAMPLE:7444", "Pulsar.EXAMPLE:7444"},
        std::pair<std::string, std::string>{label + ":1", label + ":1"},
        std::pair<std::string, std::string>{maximum + ":65535", maximum + ":65535"},
        std::pair<std::string, std::string>{maximum + "b:1", ""},
        std::pair<std::string, std::string>{label + "a:1", ""},
        std::pair<std::string, std::string>{"host-:1", ""},
        std::pair<std::string, std::string>{"a_b:1", ""},
        std::pair<std::string, std::string>{".host:1", ""},
        std::pair<std::string, std::string>{":1", ""},
        std::pair<std::string, std::string>{"host", ""},
        std::pair<std::string, std::string>{"host:0", ""},
        std::pair<std::string, std::string>{std::string("host") + '\0' + ".test:1", ""},
    };
    for (std::size_t index = 0; index < names.size(); ++index) {
        const auto& [input, expected] = names[index];
        const auto before = input;
        const auto result = Config::formatPulsar(input);
        CHECK(result.has_value() == !expected.empty());
        CHECK(result ? *result == expected : result.error().code == Status::Code::Configuration);
        CHECK(input == before);
        std::cout << "ASTRA-ADDRESS {\"kind\":\"dns\",\"case\":" << index << ",\"accepted\":" << (result ? "true" : "false") << "}\n";
    }
}

/// Checks defaults, required/duplicate options, capacity, and endpoint boundaries without identity loading or listeners.
void configuration() {

    // Minimal valid CLI; later cases append rejected or overriding options.
    const std::array<std::string_view, 3> arguments{"--galaxy=alpha", "--listen=127.0.0.1:7443", "--super=localhost:7444"};
    // Minimal parsed configuration checked against actual public defaults.
    auto parsed = Config::parse(arguments, Member::Role::Star);
    CHECK(parsed);
    CHECK(parsed->maxMembers == 64);
    CHECK(parsed->maxInbound == 128);
    CHECK(parsed->heartbeatInterval == Milliseconds(10000));
    CHECK(parsed->identity == "identity");
    CHECK(parsed->galaxy == "alpha");
    CHECK(!parsed->comet && parsed->auth && parsed->tls && parsed->cometIdentity.empty());
    CHECK(parsed->maxAdmissionRequestBytes == 4096 && parsed->maxAdmissionResponseBytes == 2 * 1024 * 1024);
    CHECK(Config::help(Member::Role::Planet).contains("Usage: planet"));
    CHECK(Config::help(Member::Role::Star).contains("default=5000"));
    for (const auto bad : {"--max-members=0", "--max-members=4097", "--max-members=1x", "--max-members=18446744073709551616", "--max-members=-1", "--galaxy=beta", "--worker-threads=2", "--role=star", "--identity=", "--pong-timeout-ms=0", "--shutdown-timeout-seconds=61"}) {
        std::vector<std::string_view> values(arguments.begin(), arguments.end());
        values.push_back(bad);
        CHECK(!Config::parse(values, Member::Role::Star));
    }

    // Split-form arguments and wildcard listener with explicit reachable advertise.
    const std::array<std::string_view, 8> separated{"--galaxy", "alpha", "--listen", "0.0.0.0:7443", "--super", "localhost:7444", "--advertise", "127.0.0.1:7443"};
    CHECK(Config::parse(separated, Member::Role::Planet));
    CHECK(!Config::parse(std::span(separated).first<6>(), Member::Role::Planet));
    CHECK(!Config::parse({}, Member::Role::Star));
    CHECK(!Endpoint::parse("127.000.0.1:7443"));
    CHECK(!Endpoint::parse("[::ffff:127.0.0.1]:7443"));
    CHECK(!Endpoint::parse("[fe80::1%2]:7443"));
    CHECK(!Endpoint::parse("224.0.0.1:7443"));
    CHECK(!Endpoint::parse("0.0.0.0:7443"));
    CHECK(!Config::formatPulsar("0.0.0.0:7443"));
    CHECK(!Config::formatPulsar("224.0.0.1:7443"));
    CHECK(Endpoint::parse("0.0.0.0:0", true));
    CHECK(Endpoint::parse("[2001:0DB8:0:0:0:0:0:1]:7443")->text() == "[2001:db8::1]:7443");
    CHECK(Member::validId("short"));
    CHECK(Member::validId(member(1).id));
    CHECK(!Member::validId(Id{}));
    CHECK(!Member::validName("alpha/beta"));
    CHECK(!Member::validName(std::string(65, 'a')));
    // Check new capacity options reach runtime/gRPC configuration after annotation parsing.
    for (const auto invalid : {"--max-admission-request-bytes=0", "--max-admission-request-bytes=1048577", "--max-admission-response-bytes=1023", "--max-admission-response-bytes=268435457"}) {
        std::vector<std::string_view> values(arguments.begin(), arguments.end());
        values.push_back(invalid);
        CHECK(!Config::parse(values, Member::Role::Star));
    }
    std::vector<std::string_view> limits(arguments.begin(), arguments.end());
    limits.insert(limits.end(), {"--max-admission-request-bytes=1", "--max-admission-response-bytes=1024"});
    // Minimum legal send/receive limits must be assigned to runtime parameters.
    const auto bounded = Config::parse(limits, Member::Role::Star);
    CHECK(bounded && bounded->maxAdmissionRequestBytes == 1 && bounded->maxAdmissionResponseBytes == 1024);
    // Public endpoint/certificate configuration is explicit and separate from internal identity/port; boolean misspellings cannot downgrade protection.
    std::vector<std::string_view> publicOptions(arguments.begin(), arguments.end());
    publicOptions.insert(publicOptions.end(), {"--comet=0.0.0.0:0", "--tls=false", "--auth=false"});
    const auto plaintext = Config::parse(publicOptions, Member::Role::Star);
    CHECK(plaintext && plaintext->comet->wildcard && !plaintext->tls && !plaintext->auth && plaintext->listen.port == 7443);
    CHECK(!Config::parse(publicOptions, Member::Role::Planet));
    publicOptions.push_back("--comet-identity=public");
    CHECK(!Config::parse(publicOptions, Member::Role::Star));
    for (const auto invalid : {"--tls=TRUE", "--tls=0", "--auth=off", "--tls=false", "--auth=false", "--comet=127.0.0.1:7443", "--comet=127.0.0.1:7445", "--comet-identity=public"}) {
        std::vector<std::string_view> values(arguments.begin(), arguments.end());
        values.push_back(invalid);
        CHECK(!Config::parse(values, Member::Role::Star));
    }
    publicOptions.assign(arguments.begin(), arguments.end());
    publicOptions.insert(publicOptions.end(), {"--comet=127.0.0.1:7445", "--comet-identity=public"});
    const auto encrypted = Config::parse(publicOptions, Member::Role::Star);
    CHECK(encrypted && encrypted->tls && encrypted->auth && encrypted->cometIdentity == "public");
    // Pulsar hostname parsing retains port and DNS-label checks after moving implementation.
    CHECK(Config::formatPulsar("Pulsar.EXAMPLE:7444") == "Pulsar.EXAMPLE:7444");
    for (const auto invalid : {"host:0", "host:65536", "host:1x", "-host:7444", "host..local:7444", "[::]:7444"}) {
        CHECK(!Config::formatPulsar(invalid));
    }
}

/// Reject malformed CLI and conflicting listener combinations before creating runtime resources.
void options() {
    const std::array<std::string_view, 3> base{"--galaxy=alpha", "--listen=127.0.0.1:7443", "--super=localhost:7444"};
    const auto refused = [](std::string_view name, const std::vector<std::string_view>& values, Member::Role role, std::string_view message) {
        const auto result = Config::parse(values, role);
        CHECK(!result);
        CHECK(result.error().code == Status::Code::Configuration && result.error().message == message);
        std::cout << "COMMON-CONFIG {\"case\":\"" << name << "\"}\n";
    };

    /// Each appended option reaches its own boundary from the same valid minimal configuration.
    struct Addition {
        /// Stable scenario identity, including separate earlier and later listener conflicts.
        std::string_view name;
        /// Star and Planet share parsing while retaining role-specific public listeners.
        Member::Role role;
        /// Borrow only literals alive throughout the complete parser call.
        std::vector<std::string_view> arguments;
        /// Require the intended refusal rather than any unrelated parse error.
        std::string_view message;
    };

    const std::array additions{
        Addition{"bare", Member::Role::Star, {"positional"}, "Expected a named option"},
        Addition{"short", Member::Role::Star, {"-g=alpha"}, "Expected a named option"},
        Addition{"missing", Member::Role::Star, {"--group"}, "Missing or oversized option value"},
        Addition{"disguised", Member::Role::Star, {"--group", "--identity=private"}, "Missing or oversized option value"},
        Addition{"group", Member::Role::Star, {"--group=bad/name"}, "Invalid endpoint, name or identity path"},
        Addition{"advertise", Member::Role::Star, {"--advertise=0.0.0.0:7443"}, "A concrete advertise endpoint is required"},
        Addition{"metrics-role", Member::Role::Planet, {"--metrics=127.0.0.1:7446"}, "Invalid or conflicting metrics listener"},
        Addition{"metrics-invalid", Member::Role::Star, {"--metrics=localhost:7446"}, "Invalid or conflicting metrics listener"},
        Addition{"metrics-private", Member::Role::Star, {"--metrics=127.0.0.1:7443"}, "Invalid or conflicting metrics listener"},
        Addition{"metrics-public", Member::Role::Star, {"--comet=127.0.0.1:7445", "--tls=false", "--metrics=127.0.0.1:7445"}, "Invalid or conflicting metrics listener"},
        Addition{"metrics-reordered", Member::Role::Star, {"--metrics=127.0.0.1:7445", "--comet=127.0.0.1:7445", "--tls=false"}, "Invalid or conflicting metrics listener"},
        Addition{"metrics-normalized", Member::Role::Star, {"--metrics=[2001:0DB8:0:0:0:0:0:1]:7445", "--comet=[2001:db8::1]:7445", "--tls=false"}, "Invalid or conflicting metrics listener"},
    };
    for (const auto& entry : additions) {
        std::vector<std::string_view> values(base.begin(), base.end());
        values.insert(values.end(), entry.arguments.begin(), entry.arguments.end());
        refused(entry.name, values, entry.role, entry.message);
    }

    /// Replace one required field instead of accidentally testing the duplicate-option guard.
    struct Replacement {
        /// Stable identity and zero-based required field position.
        std::string_view name;
        /// Select the zero-based command-line field replaced by this invalid-input case.
        std::size_t index;
        /// Each replacement is nonempty and syntactically named but semantically invalid.
        std::string_view value;
    };

    for (const auto& entry : {Replacement{"galaxy", 0, "--galaxy=bad/name"}, Replacement{"listen", 1, "--listen=localhost:7443"}, Replacement{"super", 2, "--super=0.0.0.0:7444"}}) {
        std::vector<std::string_view> values(base.begin(), base.end());
        values[entry.index] = entry.value;
        refused(entry.name, values, Member::Role::Star, "Invalid endpoint, name or identity path");
    }
    const std::string oversized = "--identity=" + std::string(4097, 'x');
    std::vector<std::string_view> values(base.begin(), base.end());
    values.push_back(oversized);
    refused("oversized", values, Member::Role::Star, "Missing or oversized option value");

    // Positive neighbors distinguish valid separate/ephemeral endpoints from the rejected collisions.
    for (const std::string_view name : {"metrics-separate", "metrics-public-separate", "metrics-zero", "metrics-both-zero"}) {
        values.assign(base.begin(), base.end());
        values.push_back(name == "metrics-zero" || name == "metrics-both-zero" ? "--metrics=127.0.0.1:0" : "--metrics=127.0.0.1:7446");
        if (name == "metrics-public-separate" || name == "metrics-both-zero") {
            values.push_back(name == "metrics-both-zero" ? "--comet=127.0.0.1:0" : "--comet=127.0.0.1:7445");
            values.push_back("--tls=false");
        }
        const auto result = Config::parse(values, Member::Role::Star);
        CHECK(result && result->metrics && result->listen.port == 7443);
        CHECK(result->metrics->port == (name == "metrics-zero" || name == "metrics-both-zero" ? 0 : 7446));
        CHECK(result->comet.has_value() == (name == "metrics-public-separate" || name == "metrics-both-zero"));
        if (result->comet) {
            CHECK(result->comet->port == (name == "metrics-both-zero" ? 0 : 7445) && !result->tls && result->auth);
        }
        std::cout << "COMMON-CONFIG {\"case\":\"" << name << "\"}\n";
    }
    // A refusal cannot poison a later parse or alter the default listener and authentication policy.
    const auto result = Config::parse(base, Member::Role::Star);
    CHECK(result && !result->metrics && !result->comet && result->auth && result->tls && result->galaxy == "alpha");
    std::cout << "COMMON-CONFIG {\"case\":\"after-refusal\"}\nCOMMON-CONFIG {\"complete\":true}\n";
}

/// Checks Star single-stream arbitration, duplicate rejection, newer-epoch replacement, and existing inbound Planet limits.
void stars() {

    // Default Config with scenario-specific Galaxy, role, or capacity overrides.
    Config config;
    config.galaxy = "alpha";
    config.maxMembers = 3;
    // Independent uninitialized policy without actual network connections.
    Star topology(config);
    // Local test identity; later Members define remote/candidate relationships.
    const auto a = member(1), b = member(2);
    // Owned ID-sorted Member copies borrowed only during initialize.
    std::array list{a, b};
    CHECK(topology.initialize(a, list));
    CHECK(topology.status().members == 2);
    CHECK(!topology.initialize(a, list));
    // Selected outbound targets; repeated due must not return an already-pending Member.
    auto targets = topology.due(Steady::now());
    CHECK(targets);
    CHECK(!topology.due(Steady::now()));
    CHECK(topology.accept(b, Policy::Direction::Outbound, {1}, *targets));
    CHECK(!topology.accept(b, Policy::Direction::Inbound, {2}, std::nullopt));
    CHECK(!topology.accept(b, Policy::Direction::Inbound, {3}, std::nullopt));
    // Remote b copy with newer epoch replaces the existing sole Session.
    auto next = b;
    next.epoch = Member::Epoch{2};
    next.id += "/restart";
    // Displaced generations to cancel; new inbound Session remains valid after acceptance.
    auto replacement = topology.accept(next, Policy::Direction::Inbound, {4}, std::nullopt);
    CHECK(replacement && replacement->size() == 1);
    topology.closed({1}, {}, Steady::now());
    CHECK(topology.status().inbound == 1);
    CHECK(!topology.accept(b, Policy::Direction::Outbound, {5}, *targets));
    CHECK(topology.status().members == 2);
    CHECK(!topology.accept(a, Policy::Direction::Inbound, {6}, std::nullopt));
    // Independent Planet role may occupy inbound Star slots only.
    const auto planet = member(3, Member::Role::Planet);
    CHECK(topology.accept(planet, Policy::Direction::Inbound, {7}, std::nullopt));
    CHECK(topology.status().members == 2 && topology.status().planetInbound == 1);
    CHECK(!topology.accept(planet, Policy::Direction::Outbound, {8}, std::nullopt));
    // New-epoch Member copy with group changed tests equal-epoch identity immutability.
    auto conflict = next;
    conflict.group = "changed";
    CHECK(!topology.accept(conflict, Policy::Direction::Outbound, {9}, std::nullopt));
}

/// pending grants one dial responsibility; failure for an old target cannot release a newer target's marker.
void singleDialOwnership() {

    // Default Config with scenario-specific Galaxy, role, or capacity overrides.
    Config config;
    config.galaxy = "alpha";
    // Independent uninitialized policy without actual network connections.
    Star topology(config);
    // Local test identity; later Members define remote/candidate relationships.
    const auto a = member(1), b = member(2), c = member(3);
    // Shared monotonic anchor with explicit offsets for backoff, without sleeps.
    const auto now = Steady::now();
    CHECK(!topology.due(now));
    CHECK(topology.initialize(a, std::array{a, b, c}));
    // Two independent dial responsibilities; due must not select pending targets again.
    const auto first = topology.due(now), second = topology.due(now);
    CHECK(first && second && *first != *second);
    CHECK(!topology.due(now));
    topology.failed(*first, Status::Code::Transport, now);
    CHECK(!topology.due(now));
    // Target selected after backoff preserves identity and sole dial ownership.
    const auto retry = topology.due(now + config.reconnectMax);
    CHECK(retry == first && !topology.due(now + config.reconnectMax));

    // Late old-dial failure cannot return the new instance's pending slot.
    // Candidate copy with new process ID and epoch models same-deployment restart.
    auto restarted = *first;
    restarted.id += "/restart";
    ++restarted.epoch.value;
    CHECK(topology.accept(restarted, Policy::Direction::Inbound, {20}, std::nullopt));
    CHECK(!topology.due(now + config.reconnectMax));
    topology.closed({20}, Status::Code::Transport, now);
    // New-epoch dial target; late old-target failure cannot clear its pending state.
    const auto replacement = topology.due(now + config.reconnectMax);
    CHECK(replacement && *replacement == restarted);
    topology.failed(*first, Status::Code::Transport, now);
    CHECK(!topology.due(now + config.reconnectMax));
    CHECK(topology.accept(restarted, Policy::Direction::Outbound, {21}, replacement));
    CHECK(topology.status().outbound == 1);
}

/// Simultaneous dials must choose the same logical stream at both ends under either arrival order and isolate late completion.
void arbitration() {

    // a's ID is lower than b, so arbitration retains a's initiated stream without a global arbiter.
    Config config;
    config.galaxy = "alpha";
    const auto a = member(1), b = member(2);
    const auto now = Steady::now();
    for (const bool preferredFirst : {false, true}) {
        Star left(config), right(config); // Independent policies per round, without reusing closed generations.
        CHECK(left.initialize(a, std::array{a, b}));
        CHECK(right.initialize(b, std::array{a, b}));
        const auto outbound = left.due(now), inbound = right.due(now); // Retains both concurrent dial responsibilities.
        CHECK(outbound && inbound);
        if (!preferredFirst) {
            CHECK(left.accept(b, Policy::Direction::Inbound, {1}, std::nullopt));
            CHECK(right.accept(a, Policy::Direction::Outbound, {2}, inbound));
        }
        const auto installed = left.accept(b, Policy::Direction::Outbound, {3}, outbound);
        const auto accepted = right.accept(a, Policy::Direction::Inbound, {4}, std::nullopt);
        CHECK(installed && accepted);
        CHECK(installed->size() == (preferredFirst ? 0 : 1));
        CHECK(accepted->size() == (preferredFirst ? 0 : 1));
        if (preferredFirst) {
            CHECK(!left.accept(b, Policy::Direction::Inbound, {1}, std::nullopt));
            CHECK(!right.accept(a, Policy::Direction::Outbound, {2}, inbound));
        }

        // Retired RPC completion/failure cannot close the new stream or trigger reverse dialing while inbound remains healthy.
        left.closed({1}, Status::Code::Transport, now);
        right.closed({2}, Status::Code::Transport, now);
        right.failed(*inbound, Status::Code::Transport, now);
        CHECK(left.status().outbound == 1 && left.status().inbound == 0);
        CHECK(right.status().inbound == 1 && right.status().outbound == 0);
        CHECK(!left.due(now + config.reconnectMax) && !right.due(now + config.reconnectMax));
        CHECK(!left.accept(b, Policy::Direction::Outbound, {5}, outbound));
        CHECK(!right.accept(a, Policy::Direction::Inbound, {6}, std::nullopt));

        // After the sole stream closes, both ends may retry; arbitration does not assign permanent dial responsibility.
        left.closed({3}, Status::Code::Transport, now);
        right.closed({4}, Status::Code::Transport, now);
        CHECK(left.due(now + config.reconnectMax) && right.due(now + config.reconnectMax));
    }
}

/// Checks fixed lowercase digest encoding, rejects truncation/invalid characters, and preserves cross-language bytes.
void principalEncoding() {

    // Fixed 64-character lowercase digest vector for bytewise parsing and round-trip checks.
    constexpr std::string_view encoded = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // Parsed digest checked at both ends and through complete re-encoding.
    const auto parsed = Principal::parse(encoded);
    CHECK(parsed && parsed->bytes.front() == 0x01 && parsed->bytes.back() == 0xef);
    CHECK(parsed->text() == encoded);
    CHECK(!Principal::parse(encoded.substr(1)));
    for (const char invalid : {'G', 'A', '\0', '/'}) {
        // Independent valid encoding copy; replace one byte per case to cover invalid characters.
        auto malformed = std::string(encoded);
        malformed[17] = invalid;
        CHECK(!Principal::parse(malformed));
    }
}

/// Verify atomic Star membership lists and independent incoming-role capacity.
void atomicListsAndCapacity() {

    // Default Config with scenario-specific Galaxy, role, or capacity overrides.
    Config config;
    config.galaxy = "alpha";
    config.maxMembers = 2;
    // Local test identity; later Members define remote/candidate relationships.
    const auto a = member(1), b = member(2);
    Star star(config);
    // Changes one binding field to create a conflict; original topology and capacity counts must remain intact.
    auto alias = b;
    alias.address = a.address;
    // Directory with an endpoint alias must fail completely without initializing policy state.
    std::array invalid{a, alias};
    CHECK(!star.initialize(a, invalid));
    CHECK(!star.status().initialized && star.status().members == 0);
    // Valid retry after rejection verifies the same object can initialize normally.
    std::array valid{a, b};
    CHECK(star.initialize(a, valid));
    // Format-valid control services cannot consume peer or Planet Session slots through infrastructure admission.
    for (const auto role : {Member::Role::Polaris, Member::Role::Astrolabe}) {
        CHECK(!star.accept(member(8, role), Policy::Direction::Inbound, {99}, std::nullopt));
        CHECK(!star.accept(member(8, role), Policy::Direction::Outbound, {99}, member(8, role)));
    }
    CHECK(!star.accept(member(3), Policy::Direction::Inbound, {1}, std::nullopt));
    // Star and Planet quotas are independent; exhausting one preserves the other and existing indexes.
    CHECK(star.accept(member(3, Member::Role::Planet), Policy::Direction::Inbound, {2}, std::nullopt));
    CHECK(star.accept(member(4, Member::Role::Planet), Policy::Direction::Inbound, {3}, std::nullopt));
    CHECK(!star.accept(member(5, Member::Role::Planet), Policy::Direction::Inbound, {4}, std::nullopt));
    CHECK(star.status().members == 2 && star.status().planetInbound == 2);
    alias = member(6, Member::Role::Planet);
    alias.address = b.address;
    CHECK(!star.accept(alias, Policy::Direction::Inbound, {5}, std::nullopt));
    CHECK(star.status().members == 2 && star.status().planetInbound == 2);
}

/// Reject duplicate local or remote deployment digests before commit; the same object can initialize after correction.
void initialization() {

    // Independent Star configuration with Galaxy matching generated Members.
    Config config;
    config.galaxy = "alpha";

    // Select local or first remote digest to cover both duplicate-principal paths.
    for (std::size_t principal : {0U, 1U}) {
        // IDs/addresses remain distinct and ordered; only the third principal duplicates.
        std::array members{member(1), member(2), member(3)};
        members[2].principal = members[principal].principal;
        // Initially empty identity/directory; rejection must leave no partially visible state.
        Star star(config);
        CHECK(!star.initialize(members[0], members));
        CHECK(!star.status().initialized && star.status().members == 0);

        // Correct the third principal and commit all three Members in the same instance.
        members[2] = member(3);
        CHECK(star.initialize(members[0], members));
        CHECK(star.status().initialized && star.status().members == members.size());
    }
}

/// Concurrent readers snapshot topology while writer repeatedly installs/closes Sessions; mixed counts are forbidden.
void concurrentSnapshots() {

    // Default Config with scenario-specific Galaxy, role, or capacity overrides.
    Config config;
    config.galaxy = "alpha";
    // Local test identity; later Members define remote/candidate relationships.
    const auto a = member(1), b = member(2);
    // Independent uninitialized policy without actual network connections.
    Star topology(config);
    // Immutable initial Member copies; policy updates cannot mutate them.
    const std::array list{a, b};
    CHECK(topology.initialize(a, list));
    // Initially false; readers set on inconsistent counts and assert after joining workers.
    std::atomic_bool invalid{};
    // Readers use snapshots while writers mutate logical Sessions; TSan coverage requires actual concurrency.
    const auto reader = [&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            // One independently owned topology snapshot per check, without mixing separate reads.
            const auto status = topology.status();
            if (!status.initialized || status.members != 2 || status.inbound > 1 || status.outbound != 0) {
                invalid = true;
            }
        }
    };
    {
        std::jthread first(reader), second(reader);
        for (std::uint64_t i = 1; i <= 200; ++i) {
            CHECK(topology.accept(b, Policy::Direction::Inbound, {i}, std::nullopt));
            topology.closed({i}, {}, Steady::now());
        }
    }
    CHECK(!invalid && topology.status().inbound == 0);
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        canonical();
        scopes();
        statuses();
        identities();
        addresses();
        configuration();
        options();
        stars();
        singleDialOwnership();
        arbitration();
        principalEncoding();
        atomicListsAndCapacity();
        initialization();
        concurrentSnapshots();
        // Default Config with scenario-specific Galaxy, role, or capacity overrides.
        Config config;
        CHECK(retryDelay(std::numeric_limits<std::uint32_t>::max(), config, 123) <= config.reconnectMax);
        std::cout << "PASS configuration, identity boundaries and Star fencing\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
