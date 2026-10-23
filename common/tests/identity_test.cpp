// Verify signed identity parsing and admission trust boundaries using public fixtures.
#include "check.hpp"
#include "fixture.hpp"

#include <yyjson.h>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#if defined(__linux__)
namespace astra::test {
// Exercise Linux linker faults in the caller's owned complete public credential directory.
void credentials(const std::filesystem::path& directory);
} // namespace astra::test
#endif

using namespace astra;

namespace {

// Exercise file and login boundaries only inside the caller's exclusively owned temporary directory.
void loading(const std::filesystem::path& directory) {

    const auto fixtures = std::filesystem::path(ASTRA_FIXTURES) / "star-a"; // Public, fixed test material.
    const auto endpoint = *Endpoint::parse("127.0.0.1:7443");               // The fixture's independently declared IP SAN.
    for (const auto* name : {"ca.pem", "cert.pem", "key.pem", "admission.pub", "login.json"}) {
        std::filesystem::copy_file(fixtures / name, directory / name, std::filesystem::copy_options::overwrite_existing);
    }
    const auto write = [&directory](std::string_view name, std::string_view value) {
        std::ofstream output(directory / name, std::ios::binary | std::ios::trunc); // Never modify the repository fixture.
        output.write(value.data(), static_cast<std::streamsize>(value.size()));
        output.close();
        CHECK(output);
    };
    const auto rejected = [](const auto& result, std::string_view reason) {
        CHECK(!result && result.error().code == Status::Code::Identity);
        CHECK(result.error().message == reason);
        CHECK(result.error().message.find("fixture-secret") == std::string::npos);
    };
    const auto restore = [&directory, &fixtures](std::string_view name) {
        std::filesystem::copy_file(fixtures / name, directory / name, std::filesystem::copy_options::overwrite_existing);
    };

    CHECK(Identity::load(directory, endpoint));
    for (const auto& value : {"", "[]", "{", "{\"username\":\"test\"}", "{\"username\":\"test\",\"password\":\"fixture-secret\",\"extra\":true}"}) {
        write("login.json", value);
        rejected(Identity::load(directory, endpoint), "login.json requires username and password");
    }
    for (const auto& value : {"{\"username\":false,\"password\":\"fixture-secret\"}", "{\"username\":\"test\",\"password\":null}"}) {
        write("login.json", value);
        rejected(Identity::load(directory, endpoint), "Login fields must be strings");
    }
    for (const auto& value : {"{\"username\":\"test\",\"username\":\"fixture-secret\"}", "{\"password\":\"fixture-secret\",\"password\":\"fixture-secret\"}", "{\"username\\u0000\":\"test\",\"password\":\"fixture-secret\"}"}) {
        write("login.json", value);
        rejected(Identity::load(directory, endpoint), "Unknown or duplicate login field");
    }
    for (const auto& value : {"{\"username\":\"\",\"password\":\"fixture-secret\"}", "{\"username\":\"test\",\"password\":\"\"}"}) {
        write("login.json", value);
        rejected(Identity::load(directory, endpoint), "Invalid login field bounds");
    }
    for (const std::size_t length : {std::size_t(1024), std::size_t(1025)}) {
        write("login.json", "{\"password\":\"" + std::string(length, 'x') + "\",\"username\":\"test\"}");
        const auto result = Identity::load(directory, endpoint); // Check both sides of the exact byte limit.
        if (length == 1024) {
            CHECK(result && (*result)->username() == "test" && (*result)->password() == std::string(length, 'x'));
        } else {
            rejected(result, "Invalid login field bounds");
        }
    }
    std::string padded = "{\"password\":\"fixture-secret\",\"username\":\"test\"}"; // Padding belongs to JSON whitespace, not a password.
    padded.resize(16384, ' ');
    write("login.json", padded);
    CHECK(Identity::load(directory, endpoint));
    padded += ' ';
    write("login.json", padded);
    rejected(Identity::load(directory, endpoint), "Identity file must be regular and at most 16 KiB");
    CHECK(std::filesystem::remove(directory / "login.json"));
    CHECK(std::filesystem::create_directory(directory / "login.json"));
    rejected(Identity::load(directory, endpoint), "Identity file must be regular and at most 16 KiB");
    CHECK(std::filesystem::remove(directory / "login.json"));
    rejected(Identity::load(directory, endpoint), "Identity file must be regular and at most 16 KiB");
    restore("login.json");
    for (const std::size_t length : {std::size_t(31), std::size_t(33)}) {
        write("admission.pub", std::string(length, 'x'));
        rejected(Identity::loadServer(directory, endpoint), "Missing or invalid identity materials");
    }
    restore("admission.pub");
    for (const auto* name : {"ca.pem", "cert.pem", "key.pem"}) {
        CHECK(std::filesystem::remove(directory / name));
        rejected(Identity::loadServer(directory, endpoint), "Missing or invalid identity materials");
        restore(name);
        write(name, "fixture-secret");
        rejected(Identity::loadServer(directory, endpoint), "Invalid certificate or matching private key");
        restore(name);
    }
    CHECK(Identity::load(directory, endpoint)); // Refused acquisitions do not poison the next valid load.
#if defined(__linux__)
    test::credentials(directory);
#endif
    for (const auto* name : {"ca.pem", "admission.pub", "login.json"}) {
        CHECK(std::filesystem::remove(directory / name));
    }
}

/// Public listener uses certificate/key only, without internal admission, account, or CA files; all files belong to this case's temporary directory.
void external() {

    /// Atomically creates an exclusive directory; destructor removes owned paths only.
    struct Directory {
        /// Process-owned temporary path without overwriting existing directories.
        std::filesystem::path path;

        Directory() {
            for (unsigned attempt = 0; attempt < 32; ++attempt) {
                path = std::filesystem::temp_directory_path() / ("astra-public-tls-" + std::to_string(Steady::now().time_since_epoch().count()) + "-" + std::to_string(attempt));
                if (std::filesystem::create_directory(path)) {
                    return;
                }
            }
            throw std::runtime_error("Cannot create public TLS test directory");
        }

        ~Directory() {
            std::error_code ignored; // Cleanup preserves the original test exception; normal exits explicitly check file removal.
            std::filesystem::remove_all(path, ignored);
        }
    } directory;

    const auto fixtures = std::filesystem::path(ASTRA_FIXTURES);
    for (const auto* name : {"cert.pem", "key.pem"}) {
        std::filesystem::copy_file(fixtures / "star-a" / name, directory.path / name);
    }
    const auto credentials = Identity::external(directory.path); // Must succeed without ca.pem, login.json, or admission.pub.
    if (!credentials) {
        throw std::runtime_error(credentials.error().message);
    }

    // Reject truncated intermediates after a valid leaf instead of deferring a corrupt chain to background handshakes.
    {
        std::ofstream output(directory.path / "cert.pem", std::ios::app);
        output << "\n-----BEGIN CERTIFICATE-----\nbroken\n";
    }
    CHECK(!Identity::external(directory.path));
    std::filesystem::copy_file(fixtures / "star-a/cert.pem", directory.path / "cert.pem", std::filesystem::copy_options::overwrite_existing);

    // Reject mismatched key, expired certificate, and missing files even though public TLS needs no client CA.
    std::filesystem::copy_file(fixtures / "star-b/key.pem", directory.path / "key.pem", std::filesystem::copy_options::overwrite_existing);
    CHECK(!Identity::external(directory.path));
    CHECK(!Identity::external(fixtures / "expired"));
    std::filesystem::copy_file(fixtures / "star-a/key.pem", directory.path / "key.pem", std::filesystem::copy_options::overwrite_existing);
    {
        std::ofstream output(directory.path / "cert.pem", std::ios::app); // Non-PEM bytes must not be silently ignored after a valid leaf.
        output << "\nfixture-secret\n";
    }
    CHECK(!Identity::external(directory.path));
    std::filesystem::copy_file(fixtures / "star-a/cert.pem", directory.path / "cert.pem", std::filesystem::copy_options::overwrite_existing);
    {
        std::ofstream output(directory.path / "cert.pem", std::ios::app); // A complete additional certificate and trailing whitespace remain valid.
        output << test::read(fixtures / "star-a/ca.pem") << " \t\r\n";
    }
    CHECK(Identity::external(directory.path));
    std::filesystem::copy_file(fixtures / "star-a/cert.pem", directory.path / "cert.pem", std::filesystem::copy_options::overwrite_existing);
    CHECK(std::filesystem::remove(directory.path / "key.pem"));
    CHECK(!Identity::external(directory.path));
    loading(directory.path);
    CHECK(std::filesystem::remove(directory.path / "key.pem"));
    CHECK(std::filesystem::remove(directory.path / "cert.pem"));
    CHECK(std::filesystem::remove(directory.path));
}

/// Borrows a string field from object; asserts type and bounds the view by JSON-document lifetime.
std::string_view text(yyjson_val* object, const char* field) {

    // Borrowed field pointer; verify string type before reading bytes/length.
    auto* value = yyjson_obj_get(object, field);
    CHECK(yyjson_is_str(value));
    return {yyjson_get_str(value), yyjson_get_len(value)};
}

/// Shared cross-language public vectors check names, endpoints, IDs, and deployment digests; identity is used for hashing only.
void vectors(const Identity& identity) {

    // Owns public-vector JSON; this function owns the yyjson document.
    auto json = test::read(std::filesystem::path(ASTRA_FIXTURES) / "admission-v1.json");
    std::unique_ptr<yyjson_doc, decltype(&yyjson_doc_free)> document(yyjson_read(json.data(), json.size(), 0), yyjson_doc_free);
    CHECK(document);
    // Borrows a successfully parsed root; array traversal never mutates it.
    auto* root = yyjson_doc_get_root(document.get());
    for (const auto* field : {"names", "addresses", "ids"}) {
        // Borrows the category array and reads one explicit value/valid case at a time.
        auto iterator = yyjson_arr_iter_with(yyjson_obj_get(root, field));
        while (auto* item = yyjson_arr_iter_next(&iterator)) {
            // Borrowed vector text; expectations are not derived from the parser under test.
            const auto value = text(item, "value");
            // Independent expected validity from the shared vector.
            const auto expected = yyjson_get_bool(yyjson_obj_get(item, "valid"));
            // Initially false; receives actual name, endpoint, or ID validation.
            bool actual = false;
            if (std::string_view(field) == "names") {
                actual = Member::validName(value);
            } else if (std::string_view(field) == "addresses") {
                // Parsed endpoint must re-encode identically to be canonical.
                auto endpoint = Endpoint::parse(value);
                actual = endpoint && endpoint->text() == value;
            } else {
                actual = Member::validId(value);
            }
            CHECK(actual == expected);
        }
    }
    CHECK(identity.principal("alpha", "127.0.0.1:7443").text() == "40ff2c81b912f4ba03daa166aa9ad70a81d80c2b1c33e85cf9e2c18e43a072dd");
    CHECK(identity.principal("alpha", "[2001:db8::1]:7443").text() == "50bd7de8c9248ba9c0484566d54d7f7795b4d66cb68efb4bea888b765b8551d2");
}

/// Actual raw-byte Ed25519 verification covers domain separation, unknown fields, tampering, and length bounds.
void signatures(const Identity& identity) {

    // Valid opaque Unicode/control-character ID verifies no legacy HexID interpretation.
    proto::orbit::v1::Member member;
    member.set_galaxy("alpha");
    member.set_group("default");
    member.set_id("format-vNext/カナ\"\nidentity");
    const auto digest = identity.principal("alpha", "127.0.0.1:7443");
    member.set_principal(digest.bytes.data(), digest.bytes.size());
    member.set_advertise("127.0.0.1:7443");
    member.set_epoch(1);
    member.set_role(proto::orbit::v1::ROLE_STAR);
    // Owned signed payload; later changes require a new signature.
    auto value = member.SerializeAsString();
    // Valid public-fixture signature; single-byte flips exercise rejection.
    auto signature = test::sign(value);
    // Converts borrowed sv bytes to a read-only span without copying or extending string lifetime.
    auto as_bytes = [](std::string_view sv) { return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(sv.data()), sv.size()); };
    CHECK(identity.verify(as_bytes(value), as_bytes(signature)));
    CHECK(identity.verify(as_bytes(value), as_bytes(signature))->id == member.id());
    // Signatures for other purposes cannot authorize admission.
    const auto otherPurposeSignature = test::sign(value, "proto.orbit.v1.other-purpose");
    CHECK(!identity.verify(as_bytes(value), as_bytes(otherPurposeSignature)));
    // Even equal key/payload cannot cross protocol owners; Orbit owns admission.
    const auto otherOwnerSignature = test::sign(value, "proto.astra.v1.admission");
    CHECK(!identity.verify(as_bytes(value), as_bytes(otherOwnerSignature)));
    CHECK(!identity.verify(as_bytes(value), as_bytes(test::sign(value, "wrong-domain"))));
    CHECK(!identity.verify(as_bytes(value + "\x78\x01"), as_bytes(signature)));
    // Appending an unknown field invalidates the old signature; signing the entire new payload permits acceptance.
    const auto extended = value + "\x78\x01";
    CHECK(identity.verify(as_bytes(extended), as_bytes(test::sign(extended))));
    CHECK(!identity.verify(as_bytes(value), as_bytes(signature.substr(1))));
    const std::string malformed("\x80", 1); // A valid signature cannot legitimize a truncated protobuf varint.
    const auto invalid = identity.verify(as_bytes(malformed), as_bytes(test::sign(malformed)));
    CHECK(!invalid && invalid.error().code == Status::Code::Identity && invalid.error().message == "Invalid signed member encoding");
    signature[0] ^= 1;
    CHECK(!identity.verify(as_bytes(value), as_bytes(signature)));
    CHECK(!identity.verify(as_bytes(std::string(1025, 'x')), as_bytes(std::string(64, 'x'))));
    member.set_epoch(0);
    CHECK(!decodeMember(member));
    member.set_epoch(1);
    // Every infrastructure role round-trips explicitly; unknown numeric values cannot become Star/Planet silently.
    for (const auto role : {Member::Role::Star, Member::Role::Planet, Member::Role::Polaris, Member::Role::Astrolabe}) {
        member.set_role(Identity::role(role));
        // Owned decoded Member; accepted role must equal input exactly.
        const auto decoded = decodeMember(member);
        CHECK(decoded && decoded->role == role && Identity::encode(*decoded).SerializeAsString() == member.SerializeAsString());
    }
    member.set_role(static_cast<proto::orbit::v1::Role>(99));
    CHECK(!decodeMember(member));
    CHECK(Identity::role(static_cast<Member::Role>(99)) == proto::orbit::v1::ROLE_UNSPECIFIED);
    member.set_role(proto::orbit::v1::ROLE_STAR);
    // Protobuf bytes permits malformed UTF-8; successful signature verification still requires consistent cross-language identity-shape validation.
    for (const auto& invalid : {std::string("\xff", 1), std::string("\xc0\x80", 2), std::string("\xed\xa0\x80", 3), std::string("\xf4\x90\x80\x80", 4), std::string("\xe4\xb8", 2)}) {
        member.set_id(invalid);
        value = member.SerializeAsString();
        CHECK(!Member::validId(invalid));
        CHECK(!identity.verify(as_bytes(value), as_bytes(test::sign(value))));
    }
    // Embedded NUL is valid UTF-8 identity data; never truncate as a C string or add a new restriction.
    const std::string embedded("a\0b", 3);
    member.set_id(embedded);
    CHECK(decodeMember(member) && decodeMember(member)->id == embedded);
    member.set_advertise("127.0.0.1:07443");
    CHECK(!decodeMember(member));
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        // Certificate-authorized loopback endpoint is the control for expired and wrong-SAN cases.
        const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
        // Loads current valid public certificate/account; later signature checks use its admission public key only.
        auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", endpoint);
        CHECK(identity);
        CHECK(!Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "expired", endpoint));
        CHECK(!Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("192.0.2.1:7443")));
        external();
        vectors(**identity);
        signatures(**identity);
        std::cout << "PASS shared v1 vectors, raw-byte Ed25519, local certificate validation\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
