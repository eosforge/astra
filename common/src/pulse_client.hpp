// Acquire and filter Pulsar clock observations without blocking the Runtime control loop.
#pragma once
#include "identity.hpp"
#include "pulsar.grpc.pb.h"
#include <astra/clock.hpp>

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>

namespace astra {
/// Star time sampler owns a bounded gRPC probe thread and publishes observations to business Clock.
class Sampler {
public:
    /// endpoint comes from verified registration; identity/hello are shared read-only and output must outlive destruction.
    /// Starts synchronization without blocking Runtime Session advancement or waiting on I/O workers.
    Sampler(std::string endpoint, std::shared_ptr<Identity> identity, std::shared_ptr<const proto::astra::v1::Hello> hello, Clock& output);
    /// Cancels current RPC and joins the sole worker; output is no longer accessed after return.
    ~Sampler();
    /// Forbids copying the worker or output-publication responsibility.
    Sampler(const Sampler&) = delete;
    /// Forbids replacing state still borrowed by an in-flight RPC.
    Sampler& operator=(const Sampler&) = delete;
    /// Nonblocking stop request lets Runtime cancel other Sessions concurrently; destructor joins.
    void stop() noexcept;

private:
    /// One batch is bounded by two seconds and eight requests; publication requires complete success and at least three valid samples.
    grpc::Status sample(std::stop_token stop);
    /// Staggered bounded-backoff loop catches exceptions and lowers quality without clearing the continuous-time anchor or local lease capability.
    void run(std::stop_token stop) noexcept;
    /// Cancelable interprobe and backoff wait; false on stop, without hard real-time scheduling promises.
    bool wait(std::stop_token stop, Milliseconds delay);
    /// Read-only TLS material and process admission, without plaintext passwords sent to Pulse.
    std::shared_ptr<Identity> identity_;
    /// Immutable process admission with shared lifetime covering worker and every batch RPC.
    std::shared_ptr<const proto::astra::v1::Hello> hello_;
    /// Sole output-estimate reference, with lifetime managed by Runtime.
    Clock& output_;
    /// Worker reuses Channel and Stub; each batch creates a deadline-bound logical stream only.
    std::shared_ptr<grpc::Channel> channel_;
    /// Dedicated generated Stub used only by the worker and destroyed after it stops.
    std::unique_ptr<proto::pulsar::v1::Pulse::Stub> stub_;
    /// Credential-derived scheduling stagger, not cryptographic randomness.
    std::size_t jitter_{};
    /// Worker-calibrated local rho; zero means pending calibration. Failure retries without blocking construction.
    std::uint64_t precisionNanoseconds_{};
    /// Worker-only wait lock; stop_token wakes interprobe and backoff waits.
    std::mutex waitMutex_;
    /// Condition variable for stop-interruptible interprobe and backoff waits.
    std::condition_variable_any condition_;
    /// Declared last so dependencies are ready at start and worker stops before they release.
    std::jthread worker_;
};
} // namespace astra
