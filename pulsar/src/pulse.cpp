// Serve clock synchronization samples from the calibrated Pulsar reference.
#include "pulse.hpp"

#include <astra/clock.hpp>
#include <astra/profile.hpp>

#include <grpc/support/time.h>
#include <grpcpp/alarm.h>

#include <algorithm>
#include <limits>
#include <mutex>
#include <stdexcept>

namespace astra {
namespace {
/// Asynchronous time-stream handler, released only by OnDone; callbacks never wait for the network.
class Reactor final : public grpc::ServerBidiReactor<proto::pulsar::v1::Ping, proto::pulsar::v1::Pong> {
    /// Alarm owns separate state without capturing Reactor; OnDone clears the context before releasing the handler.
    struct Expiry {
        /// Protects only TryCancel/context lifetime handoff; never spans network I/O or protects messages.
        std::mutex mutex;
        /// gRPC owns the context; the timer may call TryCancel only while nonnull and locked.
        grpc::CallbackServerContext* context{};
    };

public:
    /// Construction starts no operations and acquires no quota; gRPC cannot call OnDone before the handler returns.
    Reactor(grpc::CallbackServerContext* context, std::counting_semaphore<64>& streams, const Source& clock) : context_(context), streams_(streams), clock_(clock) {}

    /// Verify credentials once, then read asynchronously. Every failure calls Finish; quota is retained until OnDone.
    void start(const Authority& authority, const Ledger& ledger) {

        try {
            if (!streams_.try_acquire()) {
                Finish(grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, "Pulse capacity reached"));
                return;
            }
            admitted_ = true;
            // Require unique credential metadata before extracting the original bytes.
            const auto& metadata = context_->client_metadata();
            if (metadata.count("astra-admission-bin") != 1 || metadata.count("astra-signature-bin") != 1) {
                Finish(grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "Pulse credential required"));
                return;
            }

            const auto admission = metadata.find("astra-admission-bin");

            const auto signature = metadata.find("astra-signature-bin");

            const auto value = authority.identity().verify({reinterpret_cast<const std::uint8_t*>(admission->second.data()), admission->second.size()}, {reinterpret_cast<const std::uint8_t*>(signature->second.data()), signature->second.size()});
            if (!value || value->role != Member::Role::Star || !ledger.current(*value)) {
                Finish(grpc::Status(grpc::StatusCode::PERMISSION_DENIED, "Pulse credential rejected"));
                return;
            }

            // Ignore client wall-clock deadlines; enforce a server-owned three-second monotonic stream lifetime.
            expiryTarget_ = std::make_shared<Expiry>();
            expiryTarget_->context = context_;
            expiry_.Set(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(3, GPR_TIMESPAN)), [target = expiryTarget_](bool expired) {
                std::lock_guard lock(target->mutex);
                if (expired && target->context) {
                    target->context->TryCancel();
                }
            });
            StartRead(&ping_);
        } catch (...) {
            Finish(grpc::Status(grpc::StatusCode::INTERNAL, "Pulse unavailable"));
        }
    }

private:
    /// Only one Read or Write is in flight. Callbacks compute scalars and submit the next operation without network waits.
    void OnReadDone(bool ok) override {

        ASTRA_PROFILE_SCOPE("pulsar.pulse.OnReadDone");

        if (!ok) {
            Finish(context_->IsCancelled() ? grpc::Status(grpc::StatusCode::CANCELLED, "Pulse cancelled") : grpc::Status::OK);
            return;
        }
        try {
            // t1 captures public time and quality on receive; local clock availability alone does not qualify a new sample.
            const auto t1 = clock_.now();
            if (!t1 || !t1->synchronized) {
                ASTRA_PROFILE_COUNT("clock.server.ready", t1 && t1->ready);
                ASTRA_PROFILE_COUNT("clock.server.uncertainty_ns", t1 ? t1->uncertaintyNanoseconds : 0);
                ASTRA_PROFILE_COUNT("clock.server.rejected", 1);
                Finish(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized"));
                return;
            }
            if (ping_.t0() > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                ASTRA_PROFILE_COUNT("clock.server.rejected", 4);
                Finish(grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, "Invalid Pulse timestamp"));
                return;
            }

            // Reuse Pong only after write completion. Clearing and filling are included in T2-T1.
            pong_.Clear();
            pong_.set_t0(ping_.t0());
            pong_.set_t1(static_cast<std::uint64_t>(t1->time.time_since_epoch().count()));
            pong_.set_precision_ns(clock_.precision());
            // t2 uses the same public time domain as t1 and includes response preparation latency.
            const auto t2 = clock_.now();
            if (!t2 || !t2->synchronized || t2->time < t1->time || pong_.precision_ns() == 0) {
                ASTRA_PROFILE_COUNT("clock.server.rejected", 2);
                Finish(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized"));
                return;
            }
            pong_.set_t2(static_cast<std::uint64_t>(t2->time.time_since_epoch().count()));
            pong_.set_uncertainty_ns(std::max(t1->uncertaintyNanoseconds, t2->uncertaintyNanoseconds));
            pong_.set_synchronized(true);
            ASTRA_PROFILE_COUNT("clock.server.uncertainty_ns", pong_.uncertainty_ns());
            ASTRA_PROFILE_COUNT("clock.server.rejected", 0);
            StartWrite(&pong_);
        } catch (...) {
            ASTRA_PROFILE_COUNT("clock.server.rejected", 3);
            Finish(grpc::Status(grpc::StatusCode::UNAVAILABLE, "Physical time unavailable"));
        }
    }

    /// Write completion permits Pong reuse or another Read; Finish never overlaps a write.
    void OnWriteDone(bool ok) override {

        ASTRA_PROFILE_SCOPE("pulsar.pulse.OnWriteDone");

        if (!ok) {
            Finish(grpc::Status(grpc::StatusCode::CANCELLED, "Pulse write ended"));
        } else if (++responses_ == 8) {
            Finish(grpc::Status::OK);
        } else {
            StartRead(&ping_);
        }
    }

    /// Cancellation completes the sole in-flight operation with ok=false; that callback calls Finish, avoiding a competing OnCancel Finish.
    /// gRPC calls OnDone after all other reactions return, when messages and quota may be reclaimed.
    void OnDone() override {

        if (expiryTarget_) {
            {
                // Exclude late Alarm callbacks and clear the context pointer before destroying its borrower.
                std::lock_guard lock(expiryTarget_->mutex);
                expiryTarget_->context = nullptr;
            }
            expiry_.Cancel();
        }
        if (admitted_) {
            streams_.release();
        }
        delete this;
    }

    /// gRPC and the service retain the context and quota owner until OnDone.
    grpc::CallbackServerContext* context_;
    /// Borrows the service's 64-stream quota; OnDone releases a permit only when admitted_.
    std::counting_semaphore<64>& streams_;
    /// The service stops all RPCs before destroying the clock.
    const Source& clock_;
    /// Written only by the handler and read by OnDone; rejected streams never return an unacquired permit.
    bool admitted_{};
    /// Modified only by OnWriteDone; at most eight replies.
    unsigned responses_{};
    /// Lives from StartRead through its completion callback; no message queue is retained.
    proto::pulsar::v1::Ping ping_;
    /// Unchanged until OnWriteDone; cleared before constructing the next reply.
    proto::pulsar::v1::Pong pong_;
    /// Timer state outlives Reactor independently; queued callbacks see a null context after Reactor destruction.
    std::shared_ptr<Expiry> expiryTarget_;
    /// Three-second monotonic lifetime timer, sharing separate target state to make late callbacks safe.
    grpc::Alarm expiry_;
};
} // namespace

Pulse::Pulse(const Authority& authority, const Ledger& ledger, const Source& clock) : clock_(clock), authority_(authority), ledger_(ledger) {}

grpc::ServerBidiReactor<proto::pulsar::v1::Ping, proto::pulsar::v1::Pong>* Pulse::Bounce(grpc::CallbackServerContext* context) {

    ASTRA_PROFILE_SCOPE("pulsar.pulse.Pulse.Bounce");

    auto* reactor = new Reactor(context, streams_, clock_);
    reactor->start(authority_, ledger_);
    return reactor;
}
} // namespace astra
