// Own public Comet RPC entry points and their admission and lifecycle boundaries.
#pragma once
#include "access.hpp"
#include "comet.grpc.pb.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <semaphore>
#include <stop_token>
#include <string>
#include <string_view>

namespace astra {
/// Public logical-login endpoint on the separate business Server, without node admission, clock, or internal-write RPCs.
class Gateway final : public proto::comet::v1::Gateway::CallbackService {
public:
    /// Access outlives this service and every OnDone. Instance is the fixed actual Star ID.
    /// Authentication defaults on. Maximum streams including authentication: 1..65536, default 4096. Construction does not open business access.
    Gateway(Access& access, std::string instance, bool auth = true, std::ptrdiff_t maximum = 4096);
    /// Stop and drain gRPC Server before destruction; destruction neither waits on arbitrary streams nor accesses released contexts.
    ~Gateway() override = default;
    /// Opens once after the complete local startup barrier. Cannot reopen after stop; temporary Pulsar disconnection does not close business access.
    void ready() noexcept;
    /// Stops admission and cancels owned streams outside locks. Capacity releases only at OnDone; repeated calls are harmless.
    void stop() noexcept;
    /// Long-lived stream sends one confirmation, then waits for cancellation/revocation without synchronous Read or a dedicated thread.
    grpc::ServerWriteReactor<proto::comet::v1::SessionReply>* Session(grpc::CallbackServerContext* context, const proto::comet::v1::SessionRequest* request) override;
    /// Final business permission. auth=false returns an empty guard but does not open internal Scopes. Errors include fixed trailing metadata.
    std::expected<std::optional<Access::Permit>, grpc::Status> enter(grpc::CallbackServerContext& context) const;
    /// Borrows the fixed instance ID for Gateway's lifetime; requests cannot replace it.
    const std::string& instance() const noexcept;
    /// Fixed public errors excluding peer details, credentials, and payloads; this attempt is definitely unapplied.
    /// Includes version only if actually observed for this Scope; unknown never becomes zero.
    grpc::Status error(grpc::CallbackServerContext& context, grpc::StatusCode code, proto::comet::v1::Reason reason, std::string_view message, std::optional<std::uint64_t> version = {}) const;

private:
    /// Owns one successful Session RPC until self-deletion at OnDone.
    class Stream;
    /// Immediate rejection without a business Session, also deleted only after OnDone.
    class Rejected;
    /// Shared login core, without a duplicate SECRET index.
    Access& access_;
    /// Immutable running-instance ID, exposed only in public confirmations/errors.
    const std::string instance_;
    /// Whether public business authentication is required; internal identity and __ isolation are unaffected.
    const bool auth_;
    /// Session RPC quota includes authentication, pending confirmation, and cancellation draining; no idle eviction.
    std::counting_semaphore<65536> slots_;
    /// Opens only after initial data/time readiness. Once stopped, the service cannot revive.
    std::atomic_bool ready_{};
    /// Service cancellation for existing RPCs, not a substitute for Access's final commit permission.
    std::stop_source stop_;
};
} // namespace astra
