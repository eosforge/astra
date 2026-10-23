// Session contracts bridge gRPC transport and control-loop business state.
#pragma once
#include "astra.grpc.pb.h"
#include "identity.hpp"
#include <astra/policy.hpp>
#include <astra/profile.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace astra {
/// One object per logical stream. gRPC callbacks publish completion only; control loop exclusively owns protocol state and role operations.
class Session {
public:
    /// Authenticated-stream business collaborator, invoked only on Runtime's control thread, never advanced by gRPC callbacks.
    class Data {
    public:
        /// Releases private recovery candidates after stream stop without withdrawing installed sources.
        virtual ~Data() = default;
        /// Borrows one bounded decoded packet for this call only; retain no field addresses after return.
        /// Failure closes this stream for recovery at its confirmed position; success permits message release and immediate read rearming.
        virtual Result<void> receive(const proto::astra::v1::SessionPacket& packet, Steady::time_point now) = 0;
        /// Prepares at most one packet; nullptr means no suffix. Does not advance the send position.
        virtual Result<const proto::astra::v1::SessionPacket*> prepare(Steady::time_point now) = 0;
        /// Hands off ownership and confirms send position immediately before the sole StartWrite, without allocation or business preparation.
        virtual proto::astra::v1::SessionPacket take() = 0;
        /// Both peer-source initial prefixes are installed; does not imply readiness of every cluster source.
        virtual bool ready() const noexcept = 0;

        /// Bounded local work ready without network waits; defaults to none and preserves per-round Session fairness.
        virtual bool pending() const noexcept {
            return false;
        }
    };

    /// Runtime installs one collaborator after Hello admission; borrowed data state must outlive Session.
    void bind(std::unique_ptr<Data> data);
    /// Present only after verified Hello; inbound identity cannot be inferred from expected.
    const std::optional<Member>& peer() const noexcept;
    /// Negotiated packet cap for data senders, not SDK business-limit discovery.
    std::size_t capacity() const noexcept;
    /// Whether a data collaborator was installed, for one-time Runtime wiring.
    bool bound() const noexcept;
    /// True after both sources finish initial synchronization; canceled or finished streams are not currently healthy.
    bool synchronized() const noexcept;

    /// Copies config and expected, retains immutable hello and wake, and uses Runtime's unique generation.
    /// direction selects handshake flow; outbound has an authorized target, inbound has no expected. wake must not borrow Session or Runtime.
    Session(const Config& config, Policy::Direction direction, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, std::optional<Member> expected, std::function<void()> wake);

    /// Destroy through the base only after final completion is published; destruction is not cancellation.
    virtual ~Session() = default;

    /// Control-loop-only pump consumes at most one packet per round, rearms reads before send preparation, and keeps buffers separate.
    /// Borrows policy and identity for this call at monotonic now; protocol failure closes this Session and returns displaced generations for Runtime cancellation.
    std::vector<Generation> pump(Policy& policy, const Identity& identity, Steady::time_point now);

    /// Requests closure only; Runtime retains Session until final completion, preserving context and in-flight write storage.
    /// Control-loop-only: records the first error (default cancelled); repeated calls do not reset the 250 ms grace period.
    void cancel(Status::Code error = Status::Code::Cancelled);

    /// Acquire-reads final completion; true permits final-status access and Runtime reclamation.
    bool done() const;

    /// Control-loop-only Hello identity and role admission status, independent of business synchronization.
    bool installed() const;

    /// Returns this process's fixed Session generation for exact index/completion matching.
    Generation generation() const;

    /// Returns the fixed connection direction relative to this process.
    Policy::Direction direction() const;

    /// Borrows the original outbound target, or empty inbound; borrow cannot outlive Session.
    const std::optional<Member>& expected() const;

    /// Returns local close reason or empty; failed final RPC may refine generic transport only, never explicit local protocol or identity errors.
    std::optional<Status::Code> error() const;

protected:
    /// Nonblocking control-loop readiness query; defaults to accepted inbound transport, overridden for client Channel state.
    virtual bool transportReady() const {
        return true;
    }

    /// pump starts once: client StartCall or server initial metadata.
    virtual void beginCall() = 0;

    /// Submits the sole in-flight read; Session owns message through readDone and forbids reuse until consumption.
    virtual void beginRead(proto::astra::v1::SessionPacket* message) = 0;

    /// Submits the sole in-flight write; message remains valid and immutable through writeDone, with deadline already set.
    virtual void beginWrite(const proto::astra::v1::SessionPacket* message) = 0;

    /// Requests cancellation; force requires TryCancel after grace, while false may preserve remote final status.
    virtual void requestCancel(bool force) = 0;

    /// Server Finish requires no in-flight write; client returns its sole hold after external operations stop.
    /// Maps the first local error to fixed final server status; this does not imply OnDone occurred.
    virtual void finishCall(Status::Code error) = 0;

    /// Read callback publishes ok and buffer ownership, then wakes outside locks; does not parse or rearm reads.
    void readDone(bool ok);

    /// Write callback clears in-flight state, records ok, and wakes outside locks without consuming the send queue.
    void writeDone(bool ok);

    /// Metadata callback clears in-flight state, records !ok as failure, and wakes without installing identity.
    void metadataDone(bool ok);

    /// Server cancellation callback publishes closure and wakes; OnDone remains the final-completion boundary.
    void serverCancelled();

    /// Final callback invokes once, moves status, and release-publishes done; no later Session member access is allowed.
    void completed(grpc::Status status);

private:
    /// Control-loop parser validates one packet's capacity and Hello before role policy, returning old generations or a bounded error.
    /// Arguments are borrowed only for this call at monotonic now; heartbeat replies enter the bounded queue without direct transport I/O.
    Result<std::vector<Generation>> receive(const proto::astra::v1::SessionPacket& packet, Policy& policy, const Identity& identity, Steady::time_point now);

    /// Control loop moves message and absolute deadline into a four-slot queue; false when full, without resetting existing deadlines.
    bool enqueue(proto::astra::v1::SessionPacket message, Steady::time_point deadline);

    /// Session timeout and heartbeat configuration.
    Config config_;
    /// Fixed outbound or inbound direction.
    Policy::Direction direction_;
    /// Unique Session generation within this process.
    Generation generation_;
    /// Local Hello with admission identity and protocol capabilities.
    std::shared_ptr<const proto::astra::v1::Hello> hello_;
    /// Authorized expected peer for outbound connections only.
    std::optional<Member> expected_;
    /// Actual verified identity; control-thread-only and immutable after installation.
    std::optional<Member> peer_;
    /// Active Star business replication; frozen Planet path installs none.
    std::unique_ptr<Data> data_;
    /// Independent wake closure for the host control loop.
    std::function<void()> wake_;
    /// Protects I/O state shared with asynchronous callbacks.
    mutable std::mutex mutex_;

    /// Sole current receive-packet buffer for this Session.
    proto::astra::v1::SessionPacket read_;
    /// Sole in-flight send-packet buffer for this Session.
    proto::astra::v1::SessionPacket write_;

    /// Read awaits transport completion; initially false.
    bool readInflight_{};
    /// Complete unread packet awaits business consumption; initially false.
    bool readReady_{};
    /// mutex_ protects the sole write; diagnostic builds record submission-to-callback time.
    ASTRA_PROFILE_STAMP(profileWrite_);
    /// Diagnostic-only receive-completion-to-consumption interval protected by mutex_.
    ASTRA_PROFILE_STAMP(profileReady_);
    /// Read failure or EOF; initially false.
    bool readFailed_{};
    /// Write awaits network completion; initially false.
    bool writeInflight_{};
    /// Network write failed; initially false.
    bool writeFailed_{};
    /// Initial server metadata send remains in flight; initially false.
    bool metadataInflight_{};
    /// Remote cancellation observed; initially false.
    bool remoteCancelled_{};

    /// Final gRPC status, potentially containing detailed error information.
    grpc::Status finalStatus_;
    /// Atomic final-completion flag covering all underlying callbacks; initially false.
    std::atomic_bool done_{false};

    /// Following protocol fields belong exclusively to the control loop, without mutable callback sharing.
    /// Runtime took ownership and pump started; initially false.
    bool started_{};
    /// Peer Hello passed decoding, identity, and admission checks; initially false.
    bool installed_{};
    /// Finish was requested; initially false.
    bool finishCalled_{};

    /// First local close reason also identifies closing phase, avoiding a separate inconsistent flag.
    std::optional<Status::Code> error_;

    /// Deadline for bidirectional identity and capability handshake.
    Steady::time_point handshakeDeadline_;
    /// Underlying connection-readiness deadline.
    Steady::time_point connectDeadline_;
    /// Next locally initiated Ping time.
    Steady::time_point nextPing_;
    /// End of cancellation grace period.
    Steady::time_point cancelDeadline_;
    /// Completion deadline for the sole current write, if any.
    Steady::time_point writeDeadline_;

    /// Optional outstanding Ping ID and response deadline.
    std::optional<std::pair<std::uint64_t, Steady::time_point>> pendingPing_;

    /// Next heartbeat sequence, starting at 1.
    std::uint64_t nextId_ = 1;
    /// Negotiated packet-size cap; initially 4096, then recomputed from both Hellos.
    std::uint32_t maximum_ = 4096;

    /// Queued control packet and its absolute send deadline.
    struct Pending {
        /// Owned queued protocol packet.
        proto::astra::v1::SessionPacket packet;
        /// Latest permitted send completion.
        Steady::time_point deadline;
    };

    /// Four-slot control-message ring bounds backpressure.
    std::array<std::optional<Pending>, 4> queue_;
    /// Ring head index; initially zero.
    std::size_t head_{};
    /// Queued message count; initially zero.
    std::size_t queued_{};
};

/// Prepares outbound transport for target from config/identity and retained Hello/wake; returns shared ownership for Runtime before Call starts.
/// No callback-side delete this or ownership cycles; Runtime later advances with pump.
std::shared_ptr<Session> connectSession(const Config& config, const Identity& identity, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, Member target, std::function<void()> wake);

/// Inbound ServerBidiReactor retained in Runtime's Session collection.
class Inbound : public Session, public grpc::ServerBidiReactor<proto::astra::v1::SessionPacket, proto::astra::v1::SessionPacket> {
public:
    /// Borrows gRPC context through OnDone, copies config, and retains Hello/wake; Runtime registers ownership before handler return.
    Inbound(grpc::CallbackServerContext* context, const Config& config, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, std::function<void()> wake);

    /// Forwards gRPC read ok to readDone without advancing role state; false may mean closure or failure.
    void OnReadDone(bool ok) override;

    /// Forwards write ok to writeDone without reusing the send buffer.
    void OnWriteDone(bool ok) override;

    /// Publishes initial metadata-send ok to the control loop.
    void OnSendInitialMetadataDone(bool ok) override;

    /// Records gRPC cancellation without releasing the reactor.
    void OnCancel() override;

    /// Publishes final completion for Runtime-owned reclamation.
    void OnDone() override;

private:
    /// Sends credential-free initial metadata to avoid Hello deadlock while clients await response headers.
    void beginCall() override;

    /// Borrows Session receive storage for StartRead; immutable to callers until OnReadDone.
    void beginRead(proto::astra::v1::SessionPacket* message) override;

    /// Borrows immutable send storage for StartWrite; no reuse until OnWriteDone.
    void beginWrite(const proto::astra::v1::SessionPacket* message) override;

    /// Cancels server context only when forced; grace allows Finish to carry a precise rejection status.
    void requestCancel(bool force) override;

    /// Maps local error to fixed gRPC status and calls Finish; caller must ensure writes and initial metadata are complete.
    void finishCall(Status::Code error) override;

    /// Borrowed server context; gRPC controls its underlying lifetime and state.
    grpc::CallbackServerContext* context_;
};
} // namespace astra
