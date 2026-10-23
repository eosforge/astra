// Validate and prepare incoming native-source state before publishing it to Star domains.
#include "intake.hpp"

#include <astra/policy.hpp>
#include <astra/profile.hpp>

#include <grpcpp/create_channel.h>

namespace astra {
Intake::Intake(std::shared_ptr<Identity> identity, const proto::astra::v1::Hello& local, Member target, Library& output, Access& access, std::function<void()> wake) : identity_(std::move(identity)), target_(std::move(target)), receiver_(output, access), wake_(std::move(wake)) {

    // Transport settings bound encoding and probing. Hello advertises sync capacity independently of the old control stream's 4 KiB limit.
    grpc::ChannelArguments arguments;
    arguments.SetMaxReceiveMessageSize(8 * 1024 * 1024);
    arguments.SetMaxSendMessageSize(8 * 1024 * 1024);
    arguments.SetInt("grpc.enable_retries", 0);
    arguments.SetInt("grpc.keepalive_time_ms", 30000);
    arguments.SetInt("grpc.keepalive_timeout_ms", 10000);
    channel_ = grpc::CreateCustomChannel(target_.address.text(), identity_->channelCredentials(), arguments);
    stub_ = proto::polaris::v1::Almanac::NewStub(channel_);
    *output_.mutable_hello() = local;
    output_.mutable_hello()->set_max_frame_bytes(8 * 1024 * 1024);

    // Complete fallible allocation before binding the Reactor. StartCall only after control-loop ownership transfers.
    stub_->async()->Open(&context_, this);
    AddHold();
}

bool Intake::done() const noexcept {
    return done_.load(std::memory_order_acquire);
}

bool Intake::ready() const noexcept {
    return authenticated_ && !error_ && receiver_.ready();
}

const Member& Intake::target() const noexcept {
    return target_;
}

std::optional<Status::Code> Intake::error() const noexcept {
    return error_;
}

void Intake::OnReadDone(bool ok) {

    ASTRA_PROFILE_SCOPE("star.intake.Intake.OnReadDone");
    read_.store(ok ? 1 : -1, std::memory_order_release);
    wake_();
}

void Intake::OnWriteDone(bool ok) {

    ASTRA_PROFILE_SCOPE("star.intake.Intake.OnWriteDone");
    write_.store(ok ? 1 : -1, std::memory_order_release);
    wake_();
}

void Intake::OnDone(const grpc::Status&) {

    // Move wake to independent local ownership before publishing completion; the owner may immediately reclaim Reactor, so read no members afterward.
    auto wake = std::move(wake_);
    done_.store(true, std::memory_order_release);
    wake();
}

void Intake::cancel(Status::Code cause) {

    if (error_) {
        return;
    }
    error_ = cause;
    if (!started_) {
        started_ = true;
        StartCall(); // Even an unstarted binding must complete through gRPC; never destroy context directly.
    }
    context_.TryCancel();
    RemoveHold(); // Await only OnDone; submit no further reads/writes.
}

Result<void> Intake::receive() {

    ASTRA_PROFILE_SCOPE("star.intake.Intake.receive");

    if (authenticated_) {
        return receiver_.receive(input_);
    }
    if (!input_.has_hello() || input_.hello().protocol_major() != protocolMajor || input_.hello().max_frame_bytes() < 1024 || input_.hello().max_frame_bytes() > 8 * 1024 * 1024) {
        return Status::protocol("Invalid Polaris Hello");
    }
    const auto& hello = input_.hello(); // Verify original signed bytes without re-encoding.
    auto remote = identity_->verify(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(hello.admission().data()), hello.admission().size()), std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(hello.admission_signature().data()), hello.admission_signature().size()));
    if (!remote || remote->role != Member::Role::Polaris || remote->galaxy != target_.galaxy || remote->principal != target_.principal || remote->address != target_.address) {
        return Status::identity("Polaris admission does not match deployment");
    }
    if (auto replacement = supersedes(*remote, target_); !replacement) {
        return std::unexpected(replacement.error());
    }
    target_ = std::move(*remote);
    maximum_ = hello.max_frame_bytes();
    authenticated_ = true;
    return {};
}

void Intake::pump(Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.intake.Intake.pump");

    if (done() || error_) {
        return;
    }
    try {
        if (!started_) {
            started_ = true;
            writing_ = true;
            deadline_ = now + std::chrono::seconds(30);
            StartRead(&input_);
            StartWrite(&output_);
            StartCall();
        }
        if ((!authenticated_ && now >= handshake_) || (writing_ && now >= deadline_) || now - received_ >= std::chrono::seconds(75)) {
            cancel(Status::Code::Timeout);
            return;
        }

        // Acquire received/sent buffer ownership; failures cancel. EOF never implies snapshot completion.
        const auto received = read_.exchange(0, std::memory_order_acq_rel);
        const auto sent = write_.exchange(0, std::memory_order_acq_rel);
        if (received < 0 || sent < 0) {
            cancel(Status::Code::Transport);
            return;
        }
        if (sent > 0) {
            writing_ = false;
        }
        if (received > 0) {
            if (auto result = receive(); !result) {
                cancel(result.error().code);
                return;
            }
            received_ = now;
            input_.Clear();
            StartRead(&input_);
        }

        if (authenticated_ && !writing_) {
            if (auto packet = receiver_.next(maximum_)) {
                output_ = std::move(*packet); // Move a new frame only after write completion, without per-commit threads or queues.
                writing_ = true;
                deadline_ = now + std::chrono::seconds(30);
                StartWrite(&output_);
            }
        }
    } catch (...) {
        cancel(Status::Code::Internal); // Allocation/parsing failures end only this stream, preserving complete installed state.
    }
}
} // namespace astra
