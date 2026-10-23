// Issue signed membership responses from validated authority and ledger state.
#pragma once
#include "authority.hpp"
#include "ledger.hpp"
#include "orbit.grpc.pb.h"

#include <string>

namespace astra {
class Issuer final : public proto::orbit::v1::Admission::Service {
public:
    /// Owns galaxy/pulse_endpoint text and borrows authority/ledger until all registration RPCs finish.
    Issuer(std::string galaxy, std::string pulseEndpoint, const Authority& authority, Ledger& ledger);
    /// Registers after TLS account authentication; the RPC boundary translates exceptions to fixed errors without passwords or paths.
    grpc::Status Register(grpc::ServerContext* context, const proto::orbit::v1::RegistrationRequest* request, proto::orbit::v1::RegistrationResponse* response) override;
    /// Reads one committed snapshot using the current signed identity; performs no KDF, renewal, registration, or liveness probe.
    grpc::Status List(grpc::ServerContext* context, const proto::orbit::v1::DirectoryRequest* request, proto::orbit::v1::DirectoryResponse* response) override;

private:
    /// Registration is restricted to the configured Galaxy.
    const std::string galaxy_;
    /// Separate Pulse endpoint for Star sampling.
    const std::string pulseEndpoint_;
    /// Read-only password and signing material.
    const Authority& authority_;
    /// Sole durable member store.
    Ledger& ledger_;
};
} // namespace astra
