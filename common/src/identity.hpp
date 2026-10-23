// TLS identity loading, credential construction, and Ed25519 verification; generated transport types remain in the adapter layer.

#pragma once
#include "astra.pb.h"
#include "orbit.pb.h"
#include <astra/config.hpp>

#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/security/tls_certificate_provider.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace astra {

/// Only protocol v1 is accepted by production and stream probes, without legacy negotiation or downgrade.
inline constexpr std::uint32_t protocolMajor = 1;

/// Unique Orbit admission signature domain; encoding explicitly appends the NUL separator to prevent cross-domain reuse.
inline constexpr std::string_view admissionSignatureDomain = "proto.orbit.v1.admission";

/// Converts borrowed generated Member into an independently owned, format-validated value; failure returns identity.
/// Performs format and boundary checks only, without signature verification.
Result<Member> decodeMember(const proto::orbit::v1::Member& value);

/// Startup-loaded TLS and admission material shared read-only afterward; no generic full-material formatting or diagnostic output.
class Identity {
public:
    /// Converts infrastructure roles explicitly; unknown wire values return identity rather than defaulting to Star/Planet.
    static Result<Member::Role> role(proto::orbit::v1::Role value);
    /// Encodes valid internal roles; invalid values return UNSPECIFIED for send-boundary rejection.
    static proto::orbit::v1::Role role(Member::Role value);
    /// Encodes a validated Member into independently owned generated fields, without signing or sending.
    static proto::orbit::v1::Member encode(const Member& member);

    /// Loads bounded regular ca.pem, cert.pem, key.pem, admission.pub, and login.json files from directory.
    /// Validates chain, private key, and advertise IP SAN, returning a read-only shared Identity. Invalid material returns identity; allocation may return internal.
    /// No file-content output or network connection.
    static Result<std::shared_ptr<Identity>> load(const std::filesystem::path& directory, const Endpoint& advertise);

    /// Pulsar reuses TLS/public-key validation without reading node-specific login.json.
    /// directory requires ca.pem, cert.pem, key.pem, and admission.pub; advertise checks IP SAN.
    static Result<std::shared_ptr<Identity>> loadServer(const std::filesystem::path& directory, const Endpoint& advertise);

    /// Hashes username, validated cluster, and canonical endpoint separated by NUL into an owned SHA-256 Principal without retaining inputs.
    /// Password is login material only, never identity or signing-key input.
    Principal principal(std::string_view cluster, std::string_view endpoint) const;

    /// Verifies raw admission value up to 1024 bytes against a 64-byte Ed25519 signature, then decodes Protobuf without reserialization.
    /// Returns an independently owned Member or identity failure, without borrowing value.
    Result<Member> verify(std::span<const std::uint8_t> value, std::span<const std::uint8_t> signature) const;

    /// Returns shared TLS 1.3 client credentials validating server chain and target hostname, without presenting a client certificate.
    std::shared_ptr<grpc::ChannelCredentials> channelCredentials() const;

    /// Returns shared TLS 1.3 server credentials, or null on option-creation failure; client identity uses admission instead of client certificates.
    std::shared_ptr<grpc::ServerCredentials> serverCredentials() const;

    /// Loads independent public cert.pem/key.pem and validates leaf/key matching, without reading or falling back to node CA/login files.
    /// Comet validates hostname and trust normally; self-signed or complete public chains are allowed, with TLS 1.3 only.
    static Result<std::shared_ptr<grpc::ServerCredentials>> external(const std::filesystem::path& directory);

    /// Admission-only username borrow; must not outlive Identity or enter generic diagnostics.
    const std::string& username() const;

    /// Password borrow for admission requests only; never log or retain beyond Identity lifetime.
    const std::string& password() const;

private:
    /// Login username loaded from login.json; initially empty.
    std::string username_;
    /// Login password loaded from login.json; initially empty.
    std::string password_;
    /// 32-byte Ed25519 admission verification key; initially all zero.
    std::array<std::uint8_t, 32> authority_{};
    /// gRPC provider owns in-memory certificate chain and private-key material.
    std::shared_ptr<grpc::experimental::InMemoryCertificateProvider> provider_;
};
} // namespace astra
