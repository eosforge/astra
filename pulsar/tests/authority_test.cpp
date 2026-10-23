// Verify Pulsar authority admission from bounded files and independently check signed bytes.
#include "authority.hpp"
#include "pulsar_test.hpp"

#include <openssl/curve25519.h>

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string_view>
#include <vector>

using namespace astra;

namespace {
/// Read public test material without printing it in diagnostics.
std::string read(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    CHECK(input.is_open());
    const std::string result{std::istreambuf_iterator<char>(input), {}};
    CHECK(!input.bad());
    return result;
}

/// Replace only a file inside the uniquely owned fixture directory.
void write(const std::filesystem::path& path, std::string_view bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    CHECK(output.is_open());
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    CHECK(!output.fail());
}

/// Build a literal account independently of the production JSON parser; arguments are JSON values.
std::string account(std::string_view name = "\"alpha\"", std::string_view salt = "\"0123456789abcdefABCDEF0123456789\"", std::string_view hash = "\"0123456789abcdefABCDEF01234567890123456789abcdefABCDEF0123456789\"", std::string_view roles = "[\"star\"]") {
    return "{\"username\":" + std::string(name) + ",\"salt\":" + std::string(salt) + ",\"hash\":" + std::string(hash) + ",\"roles\":" + std::string(roles) + '}';
}

/// JSON and its expected admission result; empty error means successful loading.
struct Case {
    /// Stable case identity, independent of payload and iteration order.
    std::string name;
    /// Owned JSON bytes, including malformed inputs and embedded NULs.
    std::string body;
    /// Exact fixed error text, never an echo of credentials or paths.
    std::string error;
};

/// Verify complete success/failure and emit only the stable case name after assertions pass.
void probe(const std::filesystem::path& directory, const Endpoint& admission, const Endpoint& pulse, std::string_view name, std::string_view error) {

    const auto result = Authority::load(directory, admission, pulse);
    if (error.empty()) {
        CHECK(result && *result);
        CHECK((*result)->keyId().size() == 64);
    } else {
        CHECK(!result);
        CHECK(result.error().code == Status::Code::Identity);
        CHECK(result.error().message == error);
    }
    std::cout << "PULSAR-AUTHORITY {\"case\":\"" << name << "\"}\n";
}

/// Exercise collection, field, type, lexical and inclusive size boundaries as one fixed table.
void accounts(const std::filesystem::path& directory, const Endpoint& endpoint) {

    const auto valid = account();
    const auto wrap = [](std::string body) { return '[' + body + ']'; };
    // Expected error categories come from the authority's public failure contract, not parser output.
    const std::vector<Case> cases{
        {"mixed-hex", wrap(valid), {}},
        {"empty-input", {}, "Invalid account collection"},
        {"root-object", "{}", "Invalid account collection"},
        {"root-null", "null", "Invalid account collection"},
        {"empty-array", "[]", "Invalid account collection"},
        {"truncated-json", "[{", "Invalid account collection"},
        {"trailing-value", wrap(valid) + "false", "Invalid account collection"},
        {"embedded-nul", wrap(valid) + std::string(1, '\0') + "false", "Invalid account collection"},
        {"entry-null", "[null]", "Invalid account fields"},
        {"entry-array", "[[]]", "Invalid account fields"},
        {"missing-fields", "[{}]", "Invalid account fields"},
        {"extra-field", wrap(valid.substr(0, valid.size() - 1) + ",\"extra\":true}"), "Invalid account fields"},
        {"unknown-field", "[{\"username\":\"alpha\",\"salt\":\"0123456789abcdefABCDEF0123456789\",\"hash\":\"0123456789abcdefABCDEF01234567890123456789abcdefABCDEF0123456789\",\"extra\":true}]", "Unknown or duplicate account field"},
        {"duplicate-field", "[{\"username\":\"alpha\",\"username\":\"beta\",\"salt\":\"0123456789abcdefABCDEF0123456789\",\"roles\":[\"star\"]}]", "Unknown or duplicate account field"},
        {"duplicate-account", '[' + valid + ',' + valid + ']', "Duplicate or incomplete account"},
        {"case-distinct", '[' + valid + ',' + account("\"Alpha\"") + ']', {}},
        {"name-type", wrap(account("17")), "Invalid account name"},
        {"name-empty", wrap(account("\"\"")), "Invalid account name"},
        {"name-space", wrap(account("\"a b\"")), "Invalid account name"},
        {"name-nul", wrap(account("\"a\\u0000b\"")), "Invalid account name"},
        {"name-unicode", wrap(account("\"\\u00e9\"")), "Invalid account name"},
        {"name-64", wrap(account('"' + std::string(64, 'a') + '"')), {}},
        {"name-65", wrap(account('"' + std::string(65, 'a') + '"')), "Invalid account name"},
        {"name-alphabet", wrap(account("\"AZaz09._-\"")), {}},
        {"salt-type", wrap(account("\"alpha\"", "false")), "Invalid account salt"},
        {"salt-short", wrap(account("\"alpha\"", '"' + std::string(31, '0') + '"')), "Invalid account salt"},
        {"salt-long", wrap(account("\"alpha\"", '"' + std::string(33, '0') + '"')), "Invalid account salt"},
        {"salt-digit", wrap(account("\"alpha\"", "\"g123456789abcdefABCDEF0123456789\"")), "Invalid account salt"},
        {"hash-type", wrap(account("\"alpha\"", "\"0123456789abcdefABCDEF0123456789\"", "null")), "Invalid account hash"},
        {"hash-short", wrap(account("\"alpha\"", "\"0123456789abcdefABCDEF0123456789\"", '"' + std::string(63, '0') + '"')), "Invalid account hash"},
        {"hash-long", wrap(account("\"alpha\"", "\"0123456789abcdefABCDEF0123456789\"", '"' + std::string(65, '0') + '"')), "Invalid account hash"},
        {"hash-digit", wrap(account("\"alpha\"", "\"0123456789abcdefABCDEF0123456789\"", '"' + std::string(63, '0') + "g\"")), "Invalid account hash"},
    };
    for (const auto& item : cases) {
        write(directory / "accounts.json", item.body);
        probe(directory, endpoint, endpoint, item.name, item.error);
    }

    const std::array<std::pair<std::string_view, std::string_view>, 9> roles{{{"roles-type", "null"}, {"roles-empty", "[]"}, {"roles-five", "[\"star\",\"planet\",\"polaris\",\"astrolabe\",\"star\"]"}, {"role-type", "[1]"}, {"role-unknown", "[\"admin\"]"}, {"role-case", "[\"Star\"]"}, {"role-nul", "[\"star\\u0000\"]"}, {"role-duplicate", "[\"star\",\"star\"]"}, {"roles-four", "[\"star\",\"planet\",\"polaris\",\"astrolabe\"]"}}};
    for (std::size_t index = 0; index < roles.size(); ++index) {
        const auto& [name, value] = roles[index];
        write(directory / "accounts.json", wrap(account("\"alpha\"", "\"0123456789abcdefABCDEF0123456789\"", "\"0123456789abcdefABCDEF01234567890123456789abcdefABCDEF0123456789\"", value)));
        probe(directory, endpoint, endpoint, name, index < 3 ? "Invalid account roles" : index < 8 ? "Invalid account role"
                                                                                                   : "");
    }

    // Both count limits fit below the separate file-byte limit, so these are independent boundaries.
    for (const auto count : {64, 65}) {
        std::string body = "[";
        for (int index = 0; index < count; ++index) {
            body += (index ? "," : "") + account("\"user-" + std::to_string(index) + '"');
        }
        body += ']';
        CHECK(body.size() < 16384);
        write(directory / "accounts.json", body);
        probe(directory, endpoint, endpoint, "accounts-" + std::to_string(count), count == 64 ? "" : "Invalid account collection");
    }
    for (const auto size : {16384U, 16385U}) {
        auto body = wrap(valid);
        body.resize(size, ' ');
        write(directory / "accounts.json", body);
        probe(directory, endpoint, endpoint, "bytes-" + std::to_string(size), size == 16384 ? "" : "Cannot load Pulsar authority");
    }
}

/// Check the fixed protocol domain with the raw public key rather than the production verifier alone.
void signatures(const Authority& authority, const std::string& key) {

    CHECK(key.size() == 32);
    for (const auto role : {proto::orbit::v1::ROLE_STAR, proto::orbit::v1::ROLE_PLANET, proto::orbit::v1::ROLE_POLARIS, proto::orbit::v1::ROLE_ASTROLABE}) {
        auto member = Identity::encode(test::member(1));
        member.set_epoch(1);
        member.set_role(role);
        proto::orbit::v1::RegistrationResponse response;
        authority.sign(member, response);
        CHECK(response.admission() == member.SerializeAsString() && response.signature().size() == 64);
        auto input = std::string("proto.orbit.v1.admission") + '\0' + response.admission();
        const auto verify = [&input, &response, &key] { return ED25519_verify(reinterpret_cast<const std::uint8_t*>(input.data()), input.size(), reinterpret_cast<const std::uint8_t*>(response.signature().data()), reinterpret_cast<const std::uint8_t*>(key.data())); };
        CHECK(verify() == 1);
        input[0] ^= 1;
        CHECK(verify() == 0);
        input[0] ^= 1;
        input.back() ^= 1;
        CHECK(verify() == 0);
        input.back() ^= 1;
        (*response.mutable_signature())[0] ^= 1;
        CHECK(verify() == 0);
        std::cout << "PULSAR-AUTHORITY {\"case\":\"signature-" << static_cast<int>(role) << "\"}\n";
    }
}
} // namespace

/// Keep every mutation within the owned copy; a held valid authority must survive later load failures.
int main() {

    try {
        test::Directory temporary;
        const auto directory = temporary.path / "identity";
        std::filesystem::copy(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", directory, std::filesystem::copy_options::recursive);
        const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
        const auto outside = *Endpoint::parse("203.0.113.1:7443");
        const auto original = read(directory / "accounts.json");
        const auto signing = read(directory / "admission.key");
        const auto key = read(directory / "admission.pub");
        auto held = Authority::load(directory, endpoint, endpoint);
        CHECK(held && *held);
        probe(directory, endpoint, endpoint, "original", {});
        probe(directory, outside, endpoint, "admission-san", "Invalid Pulsar TLS identity");
        probe(directory, endpoint, outside, "pulse-san", "Invalid Pulsar TLS identity");
        accounts(directory, endpoint);
        write(directory / "accounts.json", original);

        for (const auto name : {"admission.key", "accounts.json"}) {
            const auto path = directory / name;
            const auto saved = read(path);
            CHECK(std::filesystem::remove(path));
            probe(directory, endpoint, endpoint, std::string(name) + "-missing", "Cannot load Pulsar authority");
            CHECK(std::filesystem::create_directory(path));
            probe(directory, endpoint, endpoint, std::string(name) + "-directory", "Cannot load Pulsar authority");
            CHECK(std::filesystem::remove(path));
            write(path, std::string(16385, 'x'));
            probe(directory, endpoint, endpoint, std::string(name) + "-large", "Cannot load Pulsar authority");
            write(path, saved);
        }
        write(directory / "admission.key", "invalid private material");
        probe(directory, endpoint, endpoint, "key-invalid", "Invalid Ed25519 signing key");
        write(directory / "admission.key", read(directory / "key.pem"));
        probe(directory, endpoint, endpoint, "key-wrong-type", "Invalid Ed25519 signing key");
        write(directory / "admission.key", signing);
        auto wrong = key;
        wrong[0] ^= 1;
        write(directory / "admission.pub", wrong);
        probe(directory, endpoint, endpoint, "key-mismatch", "Admission key pair does not match");
        write(directory / "admission.pub", key.substr(1));
        probe(directory, endpoint, endpoint, "public-short", "Invalid Pulsar TLS identity");
        write(directory / "admission.pub", key);
        probe(directory, endpoint, endpoint, "restored", {});
        signatures(**held, key);
        CHECK(read(directory / "accounts.json") == original && read(directory / "admission.key") == signing && read(directory / "admission.pub") == key);
        std::cout << "PULSAR-AUTHORITY {\"complete\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
