// Node registration and owned Pulsar admission results.
#pragma once
#include "identity.hpp"
#include "orbit.grpc.pb.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace astra {
/// Owns Pulsar RPC contexts and inputs; control loop polls completion while gRPC callbacks leave role indexes untouched.
/// Admission state progresses from idle through connection readiness to registration.
class Admission {
public:
    /// Successful admission result without borrowed RPC-response buffers.
    struct Joined {
        /// Optional independent Pulse endpoint; empty on old control planes does not imply available synchronization.
        std::string pulseEndpoint;
        /// Local identity issued by successful registration.
        Member local;
        /// Star peers or Planet's Star candidates only, excluding control services.
        std::vector<Member> members;
        /// Shared node-handshake Hello containing admission credentials and signature.
        std::shared_ptr<const proto::astra::v1::Hello> hello;
        /// Separate registered control-service directory; current Star admission permits Polaris only, outside Policy peer connectivity.
        std::vector<Member> services;
    };

    /// Copies validated config and retains identity. Pulsar issues process identity; wake must be callback-safe and must not borrow Runtime.
    /// Prepares channel and stable request buffers only; destroy only after pending becomes false.
    Admission(const Config& config, std::shared_ptr<Identity> identity, std::function<void()> wake);

    /// gRPC borrows member request addresses; Admission must remain immobile until all callbacks drain.
    Admission(const Admission&) = delete;

    /// Assignment cannot replace request or context storage still borrowed by gRPC.
    Admission& operator=(const Admission&) = delete;

    /// Move construction is forbidden to preserve submitted request addresses.
    Admission(Admission&&) = delete;

    /// Move assignment is forbidden while RPCs may reference original storage.
    Admission& operator=(Admission&&) = delete;

    /// Starts an attempt only without an in-flight RPC; candidate_round changes Planet candidates, not startup identity.
    void begin(std::uint32_t candidate_round);

    /// Control-loop polling returns Joined or Status once complete, otherwise nullopt; shared state retains responses through callback completion.
    std::optional<Result<Admission::Joined>> poll();

    /// Permanently cancels from the control loop using TryCancel; keep polling until pending is false before destruction.
    void cancel();

    /// Control-loop query for unconsumed work, including connection wait; true does not mean Register was submitted.
    bool pending() const;
    /// True only when a post-registration read-only query explicitly revokes this process's credential, not for transient transport or directory conflicts.
    bool revoked() const noexcept;

private:
    /// Owned context, buffers, and completion state for one admission RPC.
    struct Call {
        /// Client context for deadline and cancellation.
        grpc::ClientContext context;
        /// RPC response buffer.
        proto::orbit::v1::RegistrationResponse response;
        /// Registered Star uses read-only List without resending password or creating a new startup identity.
        proto::orbit::v1::DirectoryResponse directory;
        /// Whether this is a read-only refresh; initially false, fixed before sending.
        bool listing{};
        /// Final gRPC status.
        grpc::Status status;
        /// Atomic callback completion flag; initially false.
        std::atomic_bool done{false};
    };

    /// Control-loop-only admission phase; callbacks publish call completion only.
    enum class Phase {
        /// No active attempt or result already consumed; begin may restart unless canceled.
        Idle,
        /// Awaiting TLS readiness under connection and total handshake deadlines.
        Connecting,
        /// Register in flight for admission or Planet candidate refresh.
        Registration
    };

    /// Submits Register only after readiness and without another in-flight call; uses remaining total budget and publishes callback completion.
    void startRegistration();

    /// After Register, checks capacity, deployment, and installed identity; returns owned directory and shared Hello.
    /// Moves raw admission bytes into Hello. Failure returns capacity or identity; initialize still checks directory role policy.
    Result<Admission::Joined> validate(proto::orbit::v1::RegistrationResponse& response);

    /// Copied node configuration.
    Config config_;
    /// Shared identity material.
    std::shared_ptr<Identity> identity_;
    /// Fixed after initial success; candidate refresh cannot silently replace this process. Initially nullopt.
    std::optional<Member> local_;
    /// Independent control-loop wake closure.
    std::function<void()> wake_;
    /// Pulsar gRPC Channel.
    std::shared_ptr<grpc::Channel> channel_;
    /// Pulsar client Stub.
    std::unique_ptr<proto::orbit::v1::Admission::Stub> stub_;
    /// Current admission phase; initially idle.
    Admission::Phase phase_{};
    /// Permanent cancellation flag; initially false.
    bool cancelled_{};
    /// Control-loop-only revocation state; never reauthenticate with a different identity to hide deployment replacement.
    bool revoked_{};
    /// Total deadline fixed by begin.
    Steady::time_point deadline_;
    /// Connection-phase deadline.
    Steady::time_point connectDeadline_;
    /// Reusable registration request.
    proto::orbit::v1::RegistrationRequest request_;
    /// Empty read-only request whose lifetime covers all List calls.
    proto::orbit::v1::DirectoryRequest query_;
    /// First successful fixed admission credential and Pulse endpoint; List never reissues or changes them.
    std::shared_ptr<const proto::astra::v1::Hello> hello_;
    /// Trusted Pulse listener address fixed by initial registration, never guessed from ordinary Member endpoints.
    std::string pulseEndpoint_;
    /// Current in-flight Call; null when absent.
    std::shared_ptr<Admission::Call> registration_;
};

} // namespace astra
