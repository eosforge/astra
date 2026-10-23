// Pulsar admission transport, asynchronous registration, and response validation.
#include "admission.hpp"

#include "rpc_status.hpp"
#include <astra/proto_proxy.hpp>

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <openssl/rand.h>

#include <algorithm>
#include <utility>

namespace astra {
namespace {
/// Maps remaining local budget to gRPC monotonic time without wall-clock conversion or deadline reset.
auto rpcDeadline(Steady::time_point deadline) {
    // remaining is total-deadline nanoseconds; expired budgets clamp to zero.
    const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(std::max(deadline - Steady::now(), Steady::duration::zero())).count();
    return gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_nanos(remaining, GPR_TIMESPAN));
}
} // namespace

/// Copies configuration and retains identity/wake while preparing stable transport and request storage.
Admission::Admission(const Config& config, std::shared_ptr<Identity> identity, std::function<void()> wake) : config_(config), identity_(std::move(identity)), wake_(std::move(wake)) {

    // Disable gRPC retries; application owns the shared startup idempotency key, total deadline, and error classification.
    grpc::ChannelArguments args;
    args.SetMaxReceiveMessageSize(static_cast<int>(config_.maxAdmissionResponseBytes));
    args.SetMaxSendMessageSize(static_cast<int>(config_.maxAdmissionRequestBytes));
    args.SetInt("grpc.enable_retries", 0);

    channel_ = grpc::CreateCustomChannel(config_.pulsar, identity_->channelCredentials(), args);

    stub_ = proto::orbit::v1::Admission::NewStub(channel_);

    // Secure 32-byte idempotency key is not Star identity; retries and candidate refreshes reuse it for this process.
    std::string requestId(32, '\0');

    if (RAND_bytes(reinterpret_cast<unsigned char*>(requestId.data()), requestId.size()) != 1) {
        throw std::runtime_error("Startup request entropy unavailable");
    }

    mutate(request_).requestId(std::move(requestId)).username(identity_->username()).password(identity_->password()).galaxy(config_.galaxy).advertise(config_.advertise.text()).role(Identity::role(config_.role)).group(config_.group);
}

/// Starts an admission attempt or candidate refresh for candidate_round only while idle and not canceled.
void Admission::begin(std::uint32_t candidate_round) {

    if (phase_ != Admission::Phase::Idle || cancelled_) {
        return;
    }

    request_.set_candidate_round(candidate_round);
    // One total handshake deadline includes connection readiness and registration; connection timeout may shorten it.
    deadline_ = Steady::now() + config_.handshakeTimeout;

    connectDeadline_ = std::min(deadline_, Steady::now() + config_.connectTimeout);

    phase_ = Admission::Phase::Connecting;

    channel_->GetState(true);
}

/// Starts asynchronous registration after channel readiness using the remaining attempt budget.
void Admission::startRegistration() {

    registration_ = std::make_shared<Admission::Call>();

    registration_->context.set_deadline(rpcDeadline(deadline_));

    phase_ = Admission::Phase::Registration;
    if (config_.role == Member::Role::Star && hello_) {
        registration_->listing = true;
        registration_->context.AddMetadata("astra-admission-bin", hello_->admission());
        registration_->context.AddMetadata("astra-signature-bin", hello_->admission_signature());
        stub_->async()->List(&registration_->context, &query_, &registration_->directory, [call = registration_, wake = wake_](grpc::Status status) {
            call->status = std::move(status); // Callback owns only this query's buffers and never touches role state.
            call->done.store(true, std::memory_order_release);
            wake();
        });
        return;
    }

    stub_->async()->Register(&registration_->context, &request_, &registration_->response, [call = registration_, wake = wake_](grpc::Status status) {
        call->status = std::move(status);
        // Release-publishes complete callback output for poll's acquire read, then independently wakes the control loop.
        call->done.store(true, std::memory_order_release);

        wake();
    });
}

/// Advances admission state and consumes one completed result; nullopt means waiting.
std::optional<Result<Admission::Joined>> Admission::poll() {

    if (phase_ == Admission::Phase::Idle) {
        return std::nullopt;
    }

    // Send registration once after channel readiness; connection and registration share the attempt deadline.
    if (phase_ == Admission::Phase::Connecting) {

        if (cancelled_ || Steady::now() >= connectDeadline_) {

            phase_ = Admission::Phase::Idle;
            return std::unexpected(Status{cancelled_ ? Status::Code::Cancelled : Status::Code::Timeout, "Pulsar connection did not become ready"});
        }

        if (channel_->GetState(true) != GRPC_CHANNEL_READY) {
            return std::nullopt;
        }

        startRegistration();
    }

    if (phase_ == Admission::Phase::Registration && registration_->done.load(std::memory_order_acquire)) {
        phase_ = Admission::Phase::Idle;
        // Consume calls on success and failure; callback retains its shared_ptr and only uses independent wake after publication.

        auto completed = std::exchange(registration_, {});
        if (completed->listing && (completed->status.error_code() == grpc::StatusCode::UNAUTHENTICATED || completed->status.error_code() == grpc::StatusCode::PERMISSION_DENIED)) {
            revoked_ = true;
        }

        if (!completed->status.ok() || cancelled_) {
            return std::unexpected(cancelled_ ? Status{Status::Code::Cancelled, "Admission cancelled"} : rpcError(completed->status));
        }

        if (completed->listing) {
            // Reuse admission verification; read-only queries neither provide nor change this process's signed identity or Pulse endpoint.
            completed->response.mutable_members()->Swap(completed->directory.mutable_members());
            completed->response.set_admission(hello_->admission());
            completed->response.set_signature(hello_->admission_signature());
            completed->response.set_pulse_endpoint(pulseEndpoint_);
        }

        return validate(completed->response);
    }
    return std::nullopt;
}

/// Validates the received RegistrationResponse before publishing admission state.
Result<Admission::Joined> Admission::validate(proto::orbit::v1::RegistrationResponse& response) {

    // Trusted TLS control plane supplies Pulse endpoint; validate its format before passing it to the independent TLS sampler.
    std::string pulseEndpoint;
    if (!response.pulse_endpoint().empty()) {

        auto endpoint = Config::formatPulsar(response.pulse_endpoint());
        if (!endpoint) {
            return Status::identity("Invalid Pulse endpoint");
        }
        pulseEndpoint = std::move(*endpoint);
    }

    // Check returned role capacity before allocating the owned Member array.
    const auto count = static_cast<std::size_t>(response.members_size());

    if (count > 8192 || (config_.role == Member::Role::Planet && count > 8)) {
        return Status::capacity("Admission list exceeds role capacity");
    }

    // Verify raw admission bytes and deployment; first admission accepts Pulsar-issued identity, while refresh cannot replace it.

    auto local = identity_->verify(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(response.admission().data()), response.admission().size()), std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(response.signature().data()), response.signature().size()));

    if (!local || local->galaxy != config_.galaxy || local->group != config_.group || local->role != config_.role || local->address != config_.advertise || local->principal != identity_->principal(config_.galaxy, config_.advertise.text()) || (local_ && *local != *local_)) {
        return Status::identity("Admission credential does not match this process");
    }

    // Convert directory messages to owned Member values; Policy initialization validates complete role relationships.
    std::vector<Member> members;
    members.reserve(count);
    // services retains control-plane targets only; explicitly enforce one Polaris rather than selecting by reachability.
    std::vector<Member> services;

    for (const auto& encoded : response.members()) {
        auto member = decodeMember(encoded);
        if (!member) {
            return std::unexpected(member.error());
        }
        if (member->galaxy != config_.galaxy) {
            return Status::identity("Directory galaxy mismatch");
        }
        if (member->role == Member::Role::Polaris && config_.role == Member::Role::Star) {
            if (!services.empty() || member->id == local->id || member->principal == local->principal || member->address == local->address) {
                return Status::identity("Conflicting Polaris deployment");
            }
            services.push_back(std::move(*member));
            continue;
        }
        if (member->role != Member::Role::Star) {
            return Status::identity("Unexpected admission directory role");
        }
        members.push_back(std::move(*member));
    }
    if (members.size() > config_.maxMembers) {
        return Status::capacity("Star directory exceeds configured capacity");
    }
    // Complete Star directory must contain this issued identity. Omission or replacement changes no cache and never triggers silent registration.
    if (config_.role == Member::Role::Star && std::ranges::find(members, *local) == members.end()) {
        return Status::identity("Directory does not contain this Star identity");
    }
    // Reject control services sharing any Star identity or endpoint, even if Policy later examines Stars only.
    if (!services.empty() && std::ranges::any_of(members, [&](const auto& member) { return member.id == services.front().id || member.principal == services.front().principal || member.address == services.front().address; })) {
        return Status::identity("Control service conflicts with Star directory");
    }

    local_ = *local;
    // Prepare shared Hello with verified admission material before publishing the complete Joined result.
    auto hello = std::make_shared<proto::astra::v1::Hello>();
    mutate(*hello).protocolMajor(protocolMajor).protocolMinor(0U).maxFrameBytes(config_.maxFrameBytes).admission(std::move(*response.mutable_admission())).admissionSignature(std::move(*response.mutable_signature()));
    hello_ = hello;
    pulseEndpoint_ = pulseEndpoint;

    return Admission::Joined{std::move(pulseEndpoint), std::move(*local), std::move(members), std::move(hello), std::move(services)};
}

/// Permanently stops new attempts and requests cancellation of any in-flight registration.
void Admission::cancel() {

    cancelled_ = true;

    if (phase_ == Admission::Phase::Registration) {
        registration_->context.TryCancel();
    }
}

/// Reports any unfinished attempt, including connection waiting before Register is sent.
bool Admission::pending() const {
    return phase_ != Admission::Phase::Idle;
}

bool Admission::revoked() const noexcept {
    return revoked_;
}
} // namespace astra
