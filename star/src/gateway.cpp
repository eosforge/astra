// Own public Comet RPC entry points and their admission and lifecycle boundaries.
#include "gateway.hpp"

#include <astra/profile.hpp>
#include <astra/types.hpp>

#include <stdexcept>

namespace astra {
/// Complete an immediately rejected session RPC without retaining authorization state.
class Gateway::Rejected final : public grpc::ServerWriteReactor<proto::comet::v1::SessionReply> {
public:
    /// Immediate definite rejection, without an Access token or successful-session slot.
    explicit Rejected(grpc::Status status) {
        Finish(status);
    }

    /// Deletes only after gRPC's final borrow, without ending other RPCs.
    void OnDone() override {
        delete this;
    }
};

/// Own one admitted session stream and its revocation callbacks until final gRPC completion.
class Gateway::Stream final : public grpc::ServerWriteReactor<proto::comet::v1::SessionReply> {
public:
    /// Session is installed in Access; all fallible response preparation precedes StartWrite.
    Stream(Gateway& owner, grpc::CallbackServerContext& context, std::shared_ptr<Access::Session> session) : owner_(owner), session_(std::move(session)), revoked_(session_->stopped(), Cancel{&context}), stopped_(owner.stop_.get_token(), Cancel{&context}) {
        reply_.set_instance(owner.instance_);
        reply_.set_session(session_->token());
    }

    /// Called once by the handler after Reactor construction. Buffer remains immutable until OnWriteDone.
    void start() noexcept {
        StartWrite(&reply_);
    }

    /// Sends no second confirmation. Waits for real cancellation; Finish waits for the sole Write to complete.
    void OnWriteDone(bool ok) override {

        if (!ok) {
            owner_.access_.close(session_);
        }
        const std::lock_guard lock(mutex_);
        writing_ = false;
        if (!ok) {
            cancelled_ = true;
        }
        finish();
    }

    /// Revoke token authorization before arranging Finish; cleanup cannot retract committed business results.
    void OnCancel() override {

        owner_.access_.close(session_);
        const std::lock_guard lock(mutex_);
        cancelled_ = true;
        finish();
    }

    /// Return capacity after all reactions and writes finish; unregister callbacks within context lifetime.
    void OnDone() override {
        owner_.access_.close(session_);
        owner_.slots_.release();
        delete this;
    }

private:
    /// Stop callback only signals transport, without Gateway-index access or network waits on the revocation stack.
    struct Cancel {
        /// gRPC retains context through Stream::OnDone return; unregister callbacks before its lifetime ends.
        grpc::CallbackServerContext* context;

        /// May race OnWriteDone; TryCancel does not replace Finish/OnDone.
        void operator()() const noexcept {
            context->TryCancel();
        }
    };

    /// Choose the sole Finish under stream mutex_, without reusing the sender before Write completion.
    void finish() {
        if (cancelled_ && !writing_ && !finished_) {
            finished_ = true;
            Finish(grpc::Status(grpc::StatusCode::CANCELLED, "Business session ended"));
        }
    }

    /// Gateway outlives Server draining; no asynchronous queue captures a destructing service.
    Gateway& owner_;
    /// Token authorization/cancellation shared by Access and this object until actual OnDone.
    std::shared_ptr<Access::Session> session_;
    /// Separate credential-revocation and server-shutdown cancellation sources, without extra threads.
    std::stop_callback<Cancel> revoked_;
    /// Service stop notification, independent of session revocation.
    std::stop_callback<Cancel> stopped_;
    /// Stable initial-confirmation buffer, unchanged through stream destruction after writing.
    proto::comet::v1::SessionReply reply_;
    /// Protects only reaction states; never held with Access or Library.
    std::mutex mutex_;
    /// Reserves the sole write initially; gRPC reactions start only after the handler returns.
    bool writing_ = true;
    /// One-way cancellation/send-failure flag.
    bool cancelled_{};
    /// Finish occurs once; OnDone is final reclamation.
    bool finished_{};
};

Gateway::Gateway(Access& access, std::string instance, bool auth, std::ptrdiff_t maximum) : access_(access), instance_(std::move(instance)), auth_(auth), slots_(maximum >= 1 && maximum <= 65536 ? maximum : 1) {
    if (!Member::validId(instance_) || maximum < 1 || maximum > 65536) {
        throw std::invalid_argument("Invalid business gateway configuration");
    }
}

void Gateway::ready() noexcept {
    ready_.store(true, std::memory_order_release);
}

void Gateway::stop() noexcept {
    stop_.request_stop();
}

const std::string& Gateway::instance() const noexcept {
    return instance_;
}

grpc::Status Gateway::error(grpc::CallbackServerContext& context, grpc::StatusCode code, proto::comet::v1::Reason reason, std::string_view message, std::optional<std::uint64_t> version) const {

    proto::comet::v1::Failure failure; // Fields come only from fixed service state, without echoing request bodies.
    failure.set_reason(reason);
    failure.set_effect(proto::comet::v1::EFFECT_UNAPPLIED);
    failure.set_instance(instance_);
    failure.set_message(message);
    if (version) {
        failure.set_version(*version);
    }
    context.AddTrailingMetadata("comet-error-bin", failure.SerializeAsString());
    return {code, std::string(message)};
}

grpc::ServerWriteReactor<proto::comet::v1::SessionReply>* Gateway::Session(grpc::CallbackServerContext* context, const proto::comet::v1::SessionRequest* request) {

    if (!ready_.load(std::memory_order_acquire) || stop_.stop_requested()) {
        return new Rejected(error(*context, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_BUSY, "Star is not accepting business sessions"));
    }
    if (!auth_) {
        return new Rejected(error(*context, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_INPUT, "Business authentication is disabled"));
    }
    if (!slots_.try_acquire()) {
        return new Rejected(error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Business session capacity exceeded"));
    }
    // Handler owns exception cleanup until transfer to Stream; afterward only OnDone returns the slot.
    std::shared_ptr<Access::Session> owns;
    bool reserved = true; // If error-receipt allocation fails, catch must not release the semaphore twice.
    try {
        const auto& secret = request->secret(); // Borrows request bytes only for this call; never caches writable Protobuf memory.
        auto session = access_.open(request->key(), {reinterpret_cast<const std::uint8_t*>(secret.data()), secret.size()});
        if (!session) {
            slots_.release();
            reserved = false;
            const auto code = session.error() == Access::Error::Denied ? grpc::StatusCode::UNAUTHENTICATED : grpc::StatusCode::RESOURCE_EXHAUSTED;
            const auto reason = session.error() == Access::Error::Denied ? proto::comet::v1::REASON_SESSION : proto::comet::v1::REASON_BUSY;
            return new Rejected(error(*context, code, reason, "Business login rejected"));
        }
        owns = std::move(*session);
        auto stream = std::make_unique<Stream>(*this, *context, owns); // Construction failure leaves authorization/slot cleanup with the handler.
        reserved = false;
        stream->start();
        return stream.release();
    } catch (...) {
        access_.close(owns);
        if (reserved) {
            slots_.release();
        }
        return new Rejected(error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Business login preparation failed"));
    }
}

std::expected<std::optional<Access::Permit>, grpc::Status> Gateway::enter(grpc::CallbackServerContext& context) const {

    ASTRA_PROFILE_SCOPE("star.gateway.Gateway.enter");

    if (!ready_.load(std::memory_order_acquire) || stop_.stop_requested()) {
        return std::unexpected(error(context, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_BUSY, "Star is not accepting business requests"));
    }
    if (!auth_) {
        return std::optional<Access::Permit>{};
    }
    // Allocation-free metadata lookup accepts exactly one raw token, without text/Base64 aliases.
    const auto range = context.client_metadata().equal_range("comet-session-bin");
    if (range.first == range.second || std::next(range.first) != range.second || range.first->second.size() != 32) {
        return std::unexpected(error(context, grpc::StatusCode::UNAUTHENTICATED, proto::comet::v1::REASON_SESSION, "Invalid business session"));
    }
    const auto& token = range.first->second;
    auto permit = access_.enter(std::string_view(token.data(), token.size()));
    if (!permit) {
        return std::unexpected(error(context, grpc::StatusCode::UNAUTHENTICATED, proto::comet::v1::REASON_SESSION, "Business session expired"));
    }
    return std::optional<Access::Permit>(std::move(*permit));
}
} // namespace astra
