// Validate and prepare incoming native-source state before publishing it to Star domains.
#pragma once
#include "identity.hpp"
#include "polaris.grpc.pb.h"
#include "receiver.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <optional>

namespace astra {
/// Star's sole Polaris receive stream. Callbacks publish I/O completion; the existing loop parses, installs, and sends.
/// Owner cancels then pumps until done before destruction; destruction never blocks awaiting gRPC.
class Intake final : public grpc::ClientBidiReactor<proto::polaris::v1::Packet, proto::polaris::v1::Packet> {
public:
    /// Identity/local are current Star material; target comes from the trusted Polaris directory. Output/Access persist across reconnection together.
    /// Wake owns an independent signal object rather than borrowing Runtime; construction starts no RPC.
    Intake(std::shared_ptr<Identity> identity, const proto::astra::v1::Hello& local, Member target, Library& output, Access& access, std::function<void()> wake);
    /// Only the control loop destroys after final completion; never cancel/free buffers still borrowed by gRPC during destruction.
    ~Intake() override = default;

    /// Keep one owner of RPC dispatch bindings and validation state; copying is forbidden.
    Intake(const Intake&) = delete;

    /// Keep one owner of RPC dispatch bindings and validation state; copying is forbidden.
    Intake& operator=(const Intake&) = delete;
    /// At most one page per control round. Now is local monotonic time; never called from gRPC callbacks.
    void pump(Steady::time_point now);
    /// Permanently cancels this stream with a fixed cause. After releasing hold, starts no new asynchronous I/O.
    void cancel(Status::Code cause = Status::Code::Cancelled);
    /// True only on actual completion, the sole safe destruction boundary.
    bool done() const noexcept;
    /// Verified stream with initial installation complete. Disconnect/cancel clears readiness without removing Library data.
    bool ready() const noexcept;
    /// Verified current Polaris; handshake may adopt a newer epoch of the same deployment without changing principal or endpoint.
    const Member& target() const noexcept;
    /// Fixed failure category, absent before cancellation; read only by control loop.
    std::optional<Status::Code> error() const noexcept;
    /// Callbacks neither parse Proto nor access business state; publishing ok transfers buffer ownership to the control loop.
    void OnReadDone(bool ok) override;
    /// Sole in-flight write completion; never reuse the frame or start another Write before it.
    void OnWriteDone(bool ok) override;
    /// Publishes final completion after transport operations end; no member access afterward.
    void OnDone(const grpc::Status& status) override;

private:
    /// Verify first-frame signature/deployment, then delegate to Receiver without re-verifying each page's public key.
    Result<void> receive();
    /// Immutable identity material retained through every callback.
    std::shared_ptr<Identity> identity_;
    /// Fixed deployment, updated to the actual peer after a valid higher-epoch handshake.
    Member target_;
    /// Private installation state; incomplete snapshots belong only to this stream.
    Receiver receiver_;
    /// Independent notification closure, moved to a local before OnDone publishes completion.
    std::function<void()> wake_;
    /// TLS channel and generated Stub retained until context completion.
    std::shared_ptr<grpc::Channel> channel_;
    /// One synchronization Stub, without per-Scope RPCs.
    std::unique_ptr<proto::polaris::v1::Almanac::Stub> stub_;
    /// Stable context; local phase deadlines/cancellation bound the stream without a short whole-stream deadline.
    grpc::ClientContext context_;
    /// Consume only after nonzero read_ with acquire; clear before the next StartRead.
    proto::polaris::v1::Packet input_;
    /// Immutable until write_ completes; initially contains local Hello.
    proto::polaris::v1::Packet output_;
    /// 0=pending, 1=success, -1=failure, release-published by the corresponding callback.
    std::atomic_int read_{};
    /// Independent write result permits one Read and one Write concurrently.
    std::atomic_int write_{};
    /// Only OnDone publishes true; an external acquire then permits whole-object destruction.
    std::atomic_bool done_{};
    /// First fixed failure category, written by control loop without retaining remote status text.
    std::optional<Status::Code> error_;
    /// Whether the first StartCall was submitted, initially false.
    bool started_{};
    /// Hello identity verified, initially false.
    bool authenticated_{};
    /// Write in flight, changed only by control loop.
    bool writing_{};
    /// Peer receive limit fixed after Hello; before it, use the local 8 MiB hard limit.
    std::size_t maximum_ = 8 * 1024 * 1024;
    /// Five-second total handshake deadline fixed at construction.
    Steady::time_point handshake_ = Steady::now() + std::chrono::seconds(5);
    /// Last complete-frame time, initially construction; cancel after 75 seconds without progress.
    Steady::time_point received_ = Steady::now();
    /// Current write deadline, fixed before each actual StartWrite.
    Steady::time_point deadline_{};
};
} // namespace astra
