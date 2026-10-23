// Acquire and filter Pulsar clock observations without blocking the Runtime control loop.
#include "pulse_client.hpp"

#include "clock_filter.hpp"
#include <astra/profile.hpp>

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>

#include <algorithm>
#include <condition_variable>

namespace astra {
/// Creates the time Channel and sampling thread; endpoint and identity remain fixed after construction.
/// endpoint, identity, and hello supply transport/admission; output receives clock observations.
Sampler::Sampler(std::string endpoint, std::shared_ptr<Identity> identity, std::shared_ptr<const proto::astra::v1::Hello> hello, Clock& output) : identity_(std::move(identity)), hello_(std::move(hello)), output_(output) {

    // Dedicated time-channel options cap sends and receives at 128 bytes and disable implicit gRPC retries.
    grpc::ChannelArguments arguments;
    arguments.SetMaxReceiveMessageSize(128);
    arguments.SetMaxSendMessageSize(128);
    arguments.SetInt("grpc.enable_retries", 0);
    channel_ = grpc::CreateCustomChannel(endpoint, identity_->channelCredentials(), arguments);
    stub_ = proto::pulsar::v1::Pulse::NewStub(channel_);
    jitter_ = std::hash<std::string>{}(hello_->admission_signature());
    worker_ = std::jthread([this](std::stop_token stop) { run(stop); });
}

/// Stop/join the worker before withdrawing output; dependent members release afterward in reverse declaration order.
Sampler::~Sampler() {

    stop();
    if (worker_.joinable()) {
        worker_.join();
    }
    output_.revoke();
}

/// Requests worker stop idempotently without blocking; destruction performs the final wait.
void Sampler::stop() noexcept {
    worker_.request_stop();
}

/// Runs eight four-timestamp probes, filters them, and publishes an estimate only on successful completion; stop cancels the batch.
grpc::Status Sampler::sample(std::stop_token stop) {

    ASTRA_PROFILE_SCOPE("common.pulse_client.Sampler.sample");

    // Context covers all eight probes under one monotonic two-second deadline and outlives stream draining.
    grpc::ClientContext context;
    context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(2, GPR_TIMESPAN)));
    context.AddMetadata("astra-admission-bin", hello_->admission());
    context.AddMetadata("astra-signature-bin", hello_->admission_signature());
    // stop_callback is destroyed before context and waits for any executing cancellation callback.
    std::stop_callback cancel(stop, [&context] { context.TryCancel(); });
    // Exclusively owns this batch's bidi RPC; blocking I/O runs only on this worker.
    auto stream = stub_->Bounce(&context);
    if (!stream) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Pulse stream unavailable");
    }

    // Filters this batch independently, without mixing observations from separate RPCs.
    Filter filter(precisionNanoseconds_);
    // Reusable send buffer; clear or modify only after Write returns.
    proto::pulsar::v1::Ping ping;
    // Reusable receive buffer; consume after successful Read without retaining cross-message references.
    proto::pulsar::v1::Pong pong;
    // Initially true; echo mismatch or clock failure invalidates the batch.
    bool valid = true;
    // Complete-response count, initially zero; publish only after all eight arrive.
    unsigned received = 0;
    // Clock or allocation exceptions must cancel and drain RPC before context destruction.
    try {
        // One in-flight request; sample T0/T3 next to actual Write/Read, not Runtime's 10 ms poll timestamp.
        for (unsigned index = 0; index < 8 && !stop.stop_requested(); ++index) {
            // Previous synchronous Write ended; clear before sampling T0 so future optional request fields stay independent.
            ping.Clear();
            // Local BOOTTIME nanoseconds sampled next to Write; reject negative time before sending.
            const auto t0 = elapsedNanoseconds(Clock::Elapsed::now());
            if (t0 < 0) {
                valid = false;
                break;
            }
            ping.set_t0(static_cast<std::uint64_t>(t0));
            if (!stream->Write(ping) || !stream->Read(&pong)) {
                break;
            }

            // Same-clock T3 sampled next to Read completion, not at control-loop polling.
            const auto t3 = Clock::Elapsed::now();
            ++received;
            if (pong.t0() != ping.t0() || !pong.synchronized()) {
                valid = false;
                break;
            }
            static_cast<void>(filter.observe(pong.t0(), pong.t1(), pong.t2(), t3, pong.precision_ns(), pong.uncertainty_ns(), pong.synchronized()));
            // Five milliseconds between probes avoids sampling only one transient queue window.
            if (index != 7 && !wait(stop, Milliseconds(5))) {
                break;
            }
        }
        if (!valid || stop.stop_requested() || received != 8) {
            context.TryCancel();
        }
        static_cast<void>(stream->WritesDone());
    } catch (...) {
        context.TryCancel();
        static_cast<void>(stream->Finish());
        throw;
    }

    // Final drained RPC status; publication requires successful completion.
    const auto status = stream->Finish();
    ASTRA_PROFILE_COUNT("clock.client.received", received);
    ASTRA_PROFILE_VALUE("clock.client.status", status.error_code());
    ASTRA_PROFILE_COUNT("clock.client.valid", valid);
    if (!valid) {
        return grpc::Status(grpc::StatusCode::DATA_LOSS, "Invalid Pulse response");
    }
    if (!status.ok()) {
        return status;
    }

    // Estimate requires at least three valid observations; output Clock still checks its uncertainty budget.
    const auto estimate = filter.result();
    ASTRA_PROFILE_COUNT("clock.client.estimate", estimate.has_value());
    if (stop.stop_requested() || received != 8 || !estimate) {
        return grpc::Status(grpc::StatusCode::UNAVAILABLE, "Insufficient Pulse samples");
    }
    const bool accepted = output_.publish(*estimate); // Distinguish model admission from transport success; DATA_LOSS is not physical clock offset.
    ASTRA_PROFILE_COUNT("clock.client.accepted", accepted);
    return accepted ? grpc::Status::OK : grpc::Status(grpc::StatusCode::DATA_LOSS, "Invalid Pulse estimate");
}

/// Staggered worker loop with bounded failure backoff; exceptions withdraw synchronization without terminating the process.
void Sampler::run(std::stop_token stop) noexcept {

    try {
        static_cast<void>(wait(stop, Milliseconds(jitter_ % 1000)));
        // Consecutive failed batches saturate at seven; success resets to the one-second sampling period.
        unsigned failures = 0;
        while (!stop.stop_requested()) {
            // Worker-only calibration failure lowers synchronization quality and retries, preserving established local timekeeping.
            grpc::Status status;
            try {
                if (precisionNanoseconds_ == 0) {
                    precisionNanoseconds_ = elapsedPrecisionNanoseconds(stop);
                }
                if (stop.stop_requested()) {
                    break;
                }
                status = sample(stop);
            } catch (...) {
                ASTRA_PROFILE_SCOPE("clock.client.failure");
                ASTRA_PROFILE_COUNT("clock.client.exception", 1); // Separate from RPC status; records no credentials or external error text.
                precisionNanoseconds_ = 0;
                output_.revoke();
                status = grpc::Status(grpc::StatusCode::UNAVAILABLE, "Pulse clock sampling unavailable");
            }
            if (status.ok()) {
                failures = 0;
            } else {
                failures = std::min(failures + 1, 7U);
                if (status.error_code() == grpc::StatusCode::PERMISSION_DENIED || status.error_code() == grpc::StatusCode::UNAUTHENTICATED || status.error_code() == grpc::StatusCode::DATA_LOSS) {
                    output_.revoke();
                }
            }

            // Disconnection ages observations only; Clock keeps advancing and creating deadlines, independently of worker wake punctuality.
            const auto delay = failures == 0 ? 1000U : std::min(100U << (failures - 1), 5000U);
            static_cast<void>(wait(stop, Milliseconds(delay + jitter_ % 201)));
        }
    } catch (...) {
        // Background exceptions neither terminate nor leave old observations synchronized forever; calibrated local time remains valid.
        output_.revoke();
    }
    output_.revoke();
}

/// Interruptible wait for delay; returns false if stop was requested.
bool Sampler::wait(std::stop_token stop, Milliseconds delay) {

    // Wait lock supports stop_token wakeup without waiting the full interval.
    std::unique_lock lock(waitMutex_);
    condition_.wait_for(lock, stop, delay, [] { return false; });
    return !stop.stop_requested();
}
} // namespace astra
