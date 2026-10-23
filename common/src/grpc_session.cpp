// gRPC Session transport and private outbound/inbound reactor implementations.

#include "grpc_session.hpp"

#include "rpc_status.hpp"
#include <astra/profile.hpp>

#include <grpcpp/create_channel.h>

#include <algorithm>
#include <limits>

namespace astra {
namespace {
/// Private outbound bidi reactor; one hold covers external reads/writes. After closure, cancel and return the hold without new I/O.
class Outbound final : public Session, public grpc::ClientBidiReactor<proto::astra::v1::SessionPacket, proto::astra::v1::SessionPacket> {
public:
    /// Prepares authorized target's TLS Channel and stable context, retaining one hold; Runtime takes ownership before StartCall.
    Outbound(const Config& config, const Identity& identity, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, Member target, std::function<void()> wake) : Session(config, Policy::Direction::Outbound, generation, std::move(hello), target, std::move(wake)) {

        // Disable transport retries and apply Session message limits.
        grpc::ChannelArguments arguments;
        arguments.SetMaxReceiveMessageSize(static_cast<int>(config.maxFrameBytes));
        arguments.SetMaxSendMessageSize(static_cast<int>(config.maxFrameBytes));
        arguments.SetInt("grpc.enable_retries", 0);

        // Channel verifies server TLS; Hello subsequently verifies node admission credentials.
        channel_ = grpc::CreateCustomChannel(target.address.text(), identity.channelCredentials(), arguments);

        channel_->GetState(true);

        stub_ = proto::astra::v1::StarTransport::NewStub(channel_);

        stub_->async()->OpenSession(&context_, this);

        AddHold();
    }

    /// OnReadDone publishes ok only; pump must consume the receive buffer before reuse.
    void OnReadDone(bool ok) override {
        readDone(ok);
    }

    /// OnWriteDone clears in-flight state and wakes; it never dequeues the next message.
    void OnWriteDone(bool ok) override {
        writeDone(ok);
    }

    /// OnDone publishes final status and completion for Runtime reclamation; never delete this here.
    void OnDone(const grpc::Status& status) override {
        completed(status);
    }

private:
    /// Queries Channel readiness without blocking; pump enforces the total connection deadline.
    bool transportReady() const override {
        return channel_->GetState(false) == GRPC_CHANNEL_READY;
    }

    /// Starts once after Runtime owns the stream and required I/O is prepared.
    void beginCall() override {
        StartCall();
    }

    /// Borrows Session receive storage with a stable address until OnReadDone.
    void beginRead(proto::astra::v1::SessionPacket* message) override {

        ASTRA_PROFILE_SCOPE("common.grpc_session.begin_read");
        StartRead(message);
    }

    /// Borrows Session send storage, immutable through OnWriteDone.
    void beginWrite(const proto::astra::v1::SessionPacket* message) override {

        ASTRA_PROFILE_SCOPE("common.grpc_session.begin_write");
        StartWrite(message);
    }

    /// force permits TryCancel after the grace period; ordinary EOF preserves remote final status, including authentication errors.
    void requestCancel(bool force) override {

        // After EOF, avoid TryCancel replacing PERMISSION_DENIED or other server status with CANCELLED.
        if (force || error() != Status::Code::Transport) {
            context_.TryCancel();
        }
    }

    /// Return the sole hold after control-loop submissions stop, permitting OnDone; clients send no server Finish status.
    void finishCall(Status::Code) override {
        RemoveHold();
    }

    /// Owned client-stream context.
    grpc::ClientContext context_;
    /// Shared underlying Channel.
    std::shared_ptr<grpc::Channel> channel_;
    /// Generated asynchronous service Stub.
    std::unique_ptr<proto::astra::v1::StarTransport::Stub> stub_;
};
} // namespace

/// Initializes Session state and fixes connection and handshake deadlines at construction.
Session::Session(const Config& config, Policy::Direction direction, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, std::optional<Member> expected, std::function<void()> wake) : config_(config), direction_(direction), generation_(generation), hello_(std::move(hello)), expected_(std::move(expected)), wake_(std::move(wake)), handshakeDeadline_(Steady::now() + config.handshakeTimeout), connectDeadline_(std::min(handshakeDeadline_, Steady::now() + config.connectTimeout)) {}

/// Moves a packet and its absolute deadline into a four-slot ring; false at capacity enforces backpressure.
bool Session::enqueue(proto::astra::v1::SessionPacket message, Steady::time_point deadline) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Session.enqueue");

    if (queued_ == queue_.size()) {
        return false;
    }

    // Internal invariant follows the capacity check; never use contracts directly for network-input validation.
    contract_assert(queued_ < queue_.size());

    queue_[(head_ + queued_) % queue_.size()] = Pending{std::move(message), deadline};
    ++queued_;
    return true;
}

/// Validates received frame size and identity, handles keepalive, and rejects unexpected packets.
Result<std::vector<Generation>> Session::receive(const proto::astra::v1::SessionPacket& packet, Policy& policy, const Identity& identity, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Session.receive");

    if (packet.ByteSizeLong() > maximum_) {
        return Status::capacity("Control message exceeds negotiated limit");
    }

    if (packet.has_rejection()) {
        return std::unexpected(Status{packet.rejection().code() == proto::astra::v1::PROTOCOL_ERROR_CODE_UNAUTHORIZED ? Status::Code::Identity : Status::Code::Protocol, "Remote star rejected session"});
    }

    if (!installed_) {
        // First frame must be compatible Hello; verify signature and role admission before installing identity and negotiated limits.
        if (!packet.has_hello() || packet.hello().protocol_major() != protocolMajor || packet.hello().max_frame_bytes() < 1024) {
            return Status::protocol("Expected compatible Hello");
        }

        auto member = identity.verify(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(packet.hello().admission().data()), packet.hello().admission().size()), std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(packet.hello().admission_signature().data()), packet.hello().admission_signature().size()));
        if (!member) {
            return std::unexpected(member.error());
        }

        auto install = policy.accept(*member, direction_, generation_, expected_);
        if (!install) {
            return std::unexpected(install.error());
        }

        peer_ = std::move(*member);
        installed_ = true;
        if (direction_ == Policy::Direction::Inbound) {
            // Admission is bearer material; inbound sends local Hello only after the caller passes admission and role validation.
            proto::astra::v1::SessionPacket reply;
            reply.mutable_hello()->CopyFrom(*hello_);
            if (!enqueue(std::move(reply), handshakeDeadline_)) {
                return Status::capacity("Hello send queue is full");
            }
        }

        maximum_ = std::min(hello_->max_frame_bytes(), packet.hello().max_frame_bytes());

        nextPing_ = now + config_.heartbeatInterval;
        return install;
    }

    // After handshake, Ping/Pong requires nonzero IDs; only a Pong matching this Session's pending Ping advances its deadline.
    if (packet.has_ping() && packet.ping().request_id() != 0) {

        proto::astra::v1::SessionPacket reply;
        reply.mutable_pong()->set_request_id(packet.ping().request_id());
        if (!enqueue(std::move(reply), now + config_.pongTimeout)) {
            return Status::capacity("Control send queue is full");
        }
    } else if (packet.has_pong() && packet.pong().request_id() != 0) {

        if (pendingPing_ && packet.pong().request_id() == pendingPing_->first) {

            pendingPing_.reset();
            nextPing_ = now + config_.heartbeatInterval;
        }
    } else if (data_) {
        const auto accepted = data_->receive(packet, now); // Process business messages outside the Session I/O lock.
        if (!accepted) {
            return std::unexpected(accepted.error());
        }
    } else {

        return Status::protocol("Unexpected control message");
    }

    return std::vector<Generation>{};
}

/// Sole control-loop entry advances transport and protocol, prepares sends, and consumes at most one received packet.
std::vector<Generation> Session::pump(Policy& policy, const Identity& identity, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Session.pump");

    if (done()) {
        return {};
    }

    if (!started_) {
        // Connection and Hello share the initial total budget, with a shorter dial cap; closure must still complete the bound client call.
        if (!error_ && !transportReady()) {
            if (now < connectDeadline_) {
                return {};
            }

            cancel(Status::Code::Timeout);
        }

        // gRPC permits I/O preparation before StartCall; Runtime owns this object before any completion callback.
        ASTRA_PROFILE_BEGIN(profileLock228, "common.grpc_session.Session.pump.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock228);
        started_ = true;
        if (!error_) {

            readInflight_ = true;
            beginRead(&read_);
            if (direction_ == Policy::Direction::Outbound) {

                write_.mutable_hello()->CopyFrom(*hello_);
                writeDeadline_ = handshakeDeadline_;
                writeInflight_ = true;
                ASTRA_PROFILE_MARK(profileWrite_);
                beginWrite(&write_);
            } else {

                metadataInflight_ = true;
            }
        }
        if (direction_ == Policy::Direction::Outbound || !error_) {
            beginCall();
        }
    }

    // Takes ownership of the completed packet; empty means none this round, without borrowing in-flight storage.
    std::optional<proto::astra::v1::SessionPacket> message;
    // Initially false; merges read, write, and remote-cancellation facts under lock.
    bool transportClosed = false;
    // Initially false; checks current write and metadata deadlines under the same lock.
    bool writeExpired = false;

    {

        ASTRA_PROFILE_BEGIN(profileLock259, "common.grpc_session.Session.pump.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock259);
        transportClosed = readFailed_ || writeFailed_ || remoteCancelled_;

        writeExpired = (writeInflight_ && now >= writeDeadline_) || (metadataInflight_ && now >= handshakeDeadline_);

        if (readReady_) {
            ASTRA_PROFILE_CONSUME(profileReady_, "common.session.ready_to_consume");
            message.emplace();
            message->Swap(&read_);
            readReady_ = false;
        }
    }

    if (transportClosed) {
        cancel(Status::Code::Transport);
    }

    // Collects old generations displaced by valid identity replacement; Runtime cancels them outside policy locks.
    std::vector<Generation> cancelled;
    // Deadlines take priority over newly arrived Pong or Hello; queuing and writing remain within original absolute deadlines.
    // Hello and Pong may have different deadlines; queue head need not expire first. Scanning four slots is independent of node count.
    const bool queuedExpired = std::ranges::any_of(queue_, [now](const auto& item) { return item && now >= item->deadline; });

    if (writeExpired || queuedExpired || (!installed_ && now >= handshakeDeadline_) || (pendingPing_ && now >= pendingPing_->second)) {
        cancel(Status::Code::Timeout);
    }

    if (!error_ && message) {
        // Owns this round's receive result; failure records this Session's reason and success transfers cancellation actions.
        auto result = [&]() -> Result<std::vector<Generation>> {
            try {
                return receive(*message, policy, identity, now);
            } catch (const std::bad_alloc&) {
                return Status::capacity("Peer receive allocation failed");
            } catch (...) {
                return Status::internal("Peer receive failed");
            }
        }();
        if (!result) {
            cancel(result.error().code);
        } else {
            cancelled = std::move(*result);
        }
    }

    if (!error_ && installed_ && !pendingPing_ && now >= nextPing_) {

        if (nextId_ == std::numeric_limits<std::uint64_t>::max()) {
            cancel(Status::Code::Protocol);
        } else {
            // Nonzero heartbeat ID after exhaustion check; requires a matching Pong.
            const auto id = nextId_++;

            pendingPing_ = std::pair{id, now + config_.pongTimeout};
            // Owns this heartbeat packet, unused after moving into the bounded queue.
            proto::astra::v1::SessionPacket ping;
            ping.mutable_ping()->set_request_id(id);

            if (!enqueue(std::move(ping), now + config_.pongTimeout)) {
                cancel(Status::Code::Capacity);
            }
        }
    }

    // After validation and business handoff, release decoded storage outside the lock and rearm before send preparation/serialization.
    // Swap separates read_ and local message; a newly delivered packet waits for the next round rather than recursive consumption.
    message.reset();

    // Prepare business data only with empty control queue and an idle write slot, without an extra encoded FIFO.
    bool writable{};
    {
        ASTRA_PROFILE_BEGIN(profileLock328, "common.grpc_session.Session.pump.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock328);
        writable = !writeInflight_ && !metadataInflight_ && !readFailed_ && !writeFailed_ && !remoteCancelled_;
        // Only the control thread rearms reads; reject in-flight, ready, or closing states so preparation-time arrivals are not overwritten.

        if (!error_ && !readFailed_ && !writeFailed_ && !remoteCancelled_ && !readInflight_ && !readReady_) {
            readInflight_ = true;
            beginRead(&read_);
        }
    }
    bool prepared{};
    if (!error_ && installed_ && data_ && queued_ == 0 && writable) {
        try {
            ASTRA_PROFILE_BEGIN(preparation, "common.session.prepare");
            const auto packet = data_->prepare(now);
            ASTRA_PROFILE_END(preparation);
            if (!packet) {
                cancel(packet.error().code);
            } else if (*packet) {
                if ((*packet)->ByteSizeLong() > maximum_) {
                    cancel(Status::Code::Capacity);
                } else {
                    prepared = true;
                }
            }
            if (!error_ && data_->pending()) {
                wake_(); // Next Scope is already in memory; no fallback timer or network event is needed, but install at most one Scope per round.
            }
        } catch (const std::bad_alloc&) {
            cancel(Status::Code::Capacity);
        } catch (...) {
            cancel(Status::Code::Internal);
        }
    }

    {
        // Locks only in-flight state; signature verification and Policy work already ran outside the lock.
        ASTRA_PROFILE_BEGIN(profileLock356, "common.grpc_session.Session.pump.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock356);
        if (error_) {
            // Prefer normal Finish with a clear error; allow at most 250 ms for reads, writes, and final status before forced cancellation.
            if (now >= cancelDeadline_) {
                requestCancel(true);
            }

            if (!writeInflight_ && !metadataInflight_ && !finishCalled_) {
                finishCalled_ = true;
                finishCall(*error_);
            }
        } else if (!readFailed_ && !writeFailed_ && !remoteCancelled_) {
            // Failure callbacks may arrive between checks; stop submissions now and advance cancellation outside the lock next round.
            if (!writeInflight_ && !metadataInflight_ && queued_ != 0) {

                write_.Swap(&queue_[head_]->packet);
                writeDeadline_ = queue_[head_]->deadline;
                queue_[head_].reset();
                head_ = (head_ + 1) % queue_.size();
                --queued_;
                writeInflight_ = true;
                ASTRA_PROFILE_MARK(profileWrite_);
                beginWrite(&write_);
            }

            if (!writeInflight_ && !metadataInflight_ && queued_ == 0 && prepared) {
                write_ = data_->take(); // Advance the source send position with StartWrite; callbacks only return the write slot.
                writeDeadline_ = now + config_.pongTimeout;
                writeInflight_ = true;
                ASTRA_PROFILE_MARK(profileWrite_);
                beginWrite(&write_);
            }

            // Read was submitted before send preparation; even if it completed meanwhile, leave consumption to the next round without another StartRead.
            // This preserves the sole receive slot and one-packet-per-round fairness.
        }
    }

    return cancelled;
}

/// Binds peer business data exactly once, after admission and before error; invalid ordering or repeated binding throws logic_error.
void Session::bind(std::unique_ptr<Data> data) {
    if (!installed_ || data_ || !data || error_) {
        throw std::logic_error("Cannot bind peer data before admission or twice");
    }
    data_ = std::move(data);
}

/// Returns the admitted peer, or empty before admission; borrow expires with this Session.
const std::optional<Member>& Session::peer() const noexcept {
    return peer_;
}

/// Returns negotiated sending-window capacity for backpressure.
std::size_t Session::capacity() const noexcept {
    return maximum_;
}

/// Reports whether peer business data is bound; required before sending business frames.
bool Session::bound() const noexcept {
    return static_cast<bool>(data_);
}

/// Reports business readiness only while data is ready, no error exists, and the stream is unfinished.
bool Session::synchronized() const noexcept {
    return data_ && data_->ready() && !error_ && !done();
}

/// Requests closure and fixes its deadline; does not destroy transport immediately, preserving graceful exit and precise errors.
void Session::cancel(Status::Code error) {

    if (!error_ && !done()) {
        error_ = error;
        cancelDeadline_ = Steady::now() + Milliseconds(250);
        requestCancel(false);
    }
}

/// Publishes asynchronous read result for the control loop.
void Session::readDone(bool ok) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Session.read_done");

    {
        // Protect callback flags and buffer handoff only; wake the control loop after unlocking.
        ASTRA_PROFILE_BEGIN(profileLock449, "common.grpc_session.Session.read_done.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock449);
        readInflight_ = false;
        ASTRA_PROFILE_MARK(profileReady_);
        readReady_ = ok;
        readFailed_ = !ok;
    }
    wake_();
}

/// Publishes asynchronous write completion.
void Session::writeDone(bool ok) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Session.write_done");

    {
        // Protect callback flags and buffer handoff only; wake the control loop after unlocking.
        ASTRA_PROFILE_BEGIN(profileLock462, "common.grpc_session.Session.write_done.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock462);
        ASTRA_PROFILE_CONSUME(profileWrite_, "common.session.write_to_callback");
        writeInflight_ = false;
        writeFailed_ = !ok;
    }
    wake_();
}

/// Publishes server-side observation of remote cancellation.
void Session::serverCancelled() {

    {
        // Protect callback flags and buffer handoff only; wake the control loop after unlocking.
        std::lock_guard lock(mutex_);
        remoteCancelled_ = true;
    }
    wake_();
}

/// Publishes initial server metadata-send completion.
void Session::metadataDone(bool ok) {

    {
        // Protect callback flags and buffer handoff only; wake the control loop after unlocking.
        std::lock_guard lock(mutex_);
        metadataInflight_ = false;
        writeFailed_ = writeFailed_ || !ok;
    }
    wake_();
}

/// Publishes the final gRPC result and marks completion.
void Session::completed(grpc::Status status) {

    finalStatus_ = std::move(status);
    // Acquire independent wake ownership before publishing done; Runtime may destroy this Session immediately afterward.
    auto wake = std::move(wake_);
    // After publication use only local wake ownership, never members; Runtime may reclaim reactor and context immediately.
    done_.store(true, std::memory_order_release);
    wake();
}

/// Acquire-reads final completion for control-loop reclamation; no member access is allowed after destruction.
bool Session::done() const {
    return done_.load(std::memory_order_acquire);
}

/// Reports verified peer admission, required before business binding.
bool Session::installed() const {
    return installed_;
}

Generation Session::generation() const {
    return generation_;
}

Policy::Direction Session::direction() const {
    return direction_;
}

const std::optional<Member>& Session::expected() const {
    return expected_;
}

/// Returns the local close reason, refining an absent or generic transport reason from failed final gRPC status only after done.
std::optional<Status::Code> Session::error() const {

    if (done() && !finalStatus_.ok() && (!error_ || *error_ == Status::Code::Transport)) {
        return rpcErrorCode(finalStatus_.error_code());
    }
    return error_;
}

/// Creates an outbound reactor from configuration, identity, generation, Hello, target, and wake; Runtime owns the result.
std::shared_ptr<Session> connectSession(const Config& config, const Identity& identity, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, Member target, std::function<void()> wake) {
    return std::make_shared<Outbound>(config, identity, generation, std::move(hello), std::move(target), std::move(wake));
}

/// Inbound construction fixes direction to inbound with no outbound expected target.
Inbound::Inbound(grpc::CallbackServerContext* context, const Config& config, Generation generation, std::shared_ptr<const proto::astra::v1::Hello> hello, std::function<void()> wake) : Session(config, Policy::Direction::Inbound, generation, std::move(hello), std::nullopt, std::move(wake)), context_(context) {}

/// Forwards read completion to Session; false reports closure or read failure.
void Inbound::OnReadDone(bool ok) {
    readDone(ok);
}

/// Forwards write completion to Session without dequeuing another frame.
void Inbound::OnWriteDone(bool ok) {
    writeDone(ok);
}

/// Forwards initial metadata-send completion to Session.
void Inbound::OnSendInitialMetadataDone(bool ok) {
    metadataDone(ok);
}

/// Marks remote cancellation and prevents new frames; does not reclaim the reactor.
void Inbound::OnCancel() {
    serverCancelled();
}

/// Final completion publishes Session state for Runtime reclamation.
void Inbound::OnDone() {
    completed(grpc::Status::OK);
}

/// Sends credential-free initial metadata so clients awaiting response headers can send Hello.
void Inbound::beginCall() {

    StartSendInitialMetadata();
}

/// Borrows caller-owned receive storage, which must not be reused until read completion.
void Inbound::beginRead(proto::astra::v1::SessionPacket* message) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Inbound.begin_read");
    StartRead(message);
}

/// Borrows immutable send storage through write completion.
void Inbound::beginWrite(const proto::astra::v1::SessionPacket* message) {

    ASTRA_PROFILE_SCOPE("common.grpc_session.Inbound.begin_write");
    StartWrite(message);
}

/// force cancels the underlying RPC immediately; otherwise the control loop completes closure.
void Inbound::requestCancel(bool force) {

    if (force) {
        context_->TryCancel();
    }
}

/// Maps local close reason to fixed gRPC status: identity to permission denied, protocol/conflict to invalid argument, otherwise canceled.
void Inbound::finishCall(Status::Code error) {

    const auto status = error == Status::Code::Identity ? grpc::StatusCode::PERMISSION_DENIED : error == Status::Code::Protocol || error == Status::Code::Conflict ? grpc::StatusCode::INVALID_ARGUMENT
                                                                                                                                                                   : grpc::StatusCode::CANCELLED;
    Finish(grpc::Status(status, "Session closed"));
}
} // namespace astra
