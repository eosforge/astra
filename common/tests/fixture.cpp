// Implement public test-fixture reading and domain-separated signing.
#include "fixture.hpp"

#include <openssl/curve25519.h>
#include <openssl/pem.h>

#include <array>
#include <cstdint>
#include <fstream>
#include <ios>
#include <iterator>
#include <stdexcept>

namespace astra::test {
std::string read(const std::filesystem::path& path) {
    // Reads the public fixture at path or throws; neither generates nor downloads missing material.
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot read public test fixture");
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string sign(std::string_view value, std::string_view domain) {
    // Repository-public Ed25519 private-key PEM, without deployment secrets or environment access.
    const auto pem = read(std::filesystem::path(ASTRA_FIXTURES) / "pulsar/admission.key");
    // Read-only parsing stream borrows pem and is destroyed before it.
    bssl::UniquePtr<BIO> input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    // Owns the parsed key; subsequent checks reject invalid format.
    bssl::UniquePtr<EVP_PKEY> key(input ? PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr) : nullptr);
    // 32-byte private seed and derived public key from public test material only.
    std::array<std::uint8_t, 32> seed{}, pub{};
    // BoringSSL seed-plus-public-key signing layout, local to this call.
    std::array<std::uint8_t, 64> secret{};
    // Initially seed capacity; parsed seed must remain exactly 32 bytes.
    auto size = seed.size();
    if (!key || EVP_PKEY_get_raw_private_key(key.get(), seed.data(), &size) != 1 || size != seed.size()) {
        throw std::runtime_error("Invalid public signing fixture");
    }
    ED25519_keypair_from_seed(pub.data(), secret.data(), seed.data());
    // Signature input is domain, NUL, and raw payload, matching production issuer/verifier encoding.
    const auto bytes = std::string(domain) + '\0' + std::string(value);
    // Fixed Ed25519 output buffer returned by value after successful signing.
    std::string signature(64, '\0');
    if (ED25519_sign(reinterpret_cast<std::uint8_t*>(signature.data()), reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), secret.data()) != 1) {
        throw std::runtime_error("Public fixture signing failed");
    }
    return signature;
}
} // namespace astra::test
