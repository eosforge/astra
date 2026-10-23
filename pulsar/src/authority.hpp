// Coordinate membership authority and admitted role state for the Pulsar service.
#pragma once
#include "identity.hpp"

#include <grpcpp/server_context.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <semaphore>
#include <string>
#include <vector>

namespace astra {
/// Pulsar signing authority; owns account digests and the private key, without member persistence.
class Authority {
public:
    /// Loads accounts and keys, verifying certificate authorization for both listeners. Failure returns no partial authority.
    static Result<std::unique_ptr<Authority>> load(const std::filesystem::path& directory, const Endpoint& admission, const Endpoint& pulse);
    /// Cleanses the Ed25519 private key; all services and requests must have stopped.
    ~Authority();
    /// Authenticates password and role using PBKDF2-SHA256/600000. At most four concurrent KDFs; overload returns immediately.
    grpc::Status authenticate(grpc::ServerContext& context, const proto::orbit::v1::RegistrationRequest& request) const;
    /// Encodes and signs a validated Member into an exclusively owned response. RPC boundaries translate exceptions to fixed errors.
    void sign(const proto::orbit::v1::Member& member, proto::orbit::v1::RegistrationResponse& response) const;
    /// Borrows the verified TLS/admission identity for this authority's lifetime, without mutation access.
    const Identity& identity() const;
    /// Signing public key digest binding the ledger to this authority; exposes no signing secret.
    std::string keyId() const;

private:
    /// Construction requires complete material validation.
    Authority() = default;

    /// Salt and digest only. Role bits: 1=Star, 2=Planet, 4=Polaris, 8=Astrolabe; no plaintext password.
    struct Account {
        /// Case-sensitive safe ASCII account name.
        std::string username;
        /// Random 16-byte salt.
        std::array<std::uint8_t, 16> salt{};
        /// 32-byte PBKDF2 digest.
        std::array<std::uint8_t, 32> hash{};
        /// Nonzero role bitset validated at startup.
        unsigned roles{};
    };

    /// Read-only verified TLS certificate and admission public key.
    std::shared_ptr<Identity> identity_;
    /// BoringSSL seed + public key representation, exactly 64 bytes.
    std::array<std::uint8_t, 64> privateKey_{};
    /// Derived from the verified public key, independently of the private-key buffer layout.
    Principal keyId_;
    /// At most 64 accounts; authentication performs read-only lookup.
    std::vector<Account> accounts_;
    /// Password work is isolated from Pulse; overload cannot create an unbounded waiting queue.
    mutable std::counting_semaphore<4> passwords_{4};
};
} // namespace astra
