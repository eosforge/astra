// Run Beacon sampling callbacks on a bounded worker queue with explicit close and drain ownership.
#pragma once
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace comet::detail {
/// Private Client sampling resources: two workers and 64 candidate slots, without using gRPC reactions or per-Beacon threads.
class Sampling {
public:
    /// Internal candidates own Beacons; no public executor interface.
    using Work = std::move_only_function<void()>;

    /// Create two workers; allocation or thread-start failure closes and joins every worker already started.
    static std::shared_ptr<Sampling> open();

    /// Close and join all workers; destruction must occur outside a sampling callback.
    ~Sampling();

    /// Join workers after close; concurrent application waiters are serialized, and workers must never wait for themselves.
    void wait();

    /// Transfer a candidate into the bounded queue; return false when closed or full so Beacon can retry within its deadline.
    bool submit(Work work);

    /// Stop accepting candidates and wake workers; accepted candidates still release their Beacon sampling ownership.
    void close() noexcept;

    /// Report whether every worker has released its final task and callback; thread handles still require wait().
    bool finished() const noexcept {
        return queue_->workers.load(std::memory_order_acquire) == 0;
    }

private:
    /// Fixed-capacity candidate queue shared by the manager and its two worker loops.
    struct Queue {
        /// Never held across user sampling or synchronous RPC.
        std::mutex mutex;
        /// Waits on an empty queue without polling.
        std::condition_variable ready;
        /// Fixed slots, without growth.
        std::array<Work, 64> items;
        /// Current queue head.
        std::size_t head{};
        /// Number of accepted candidates.
        std::size_t count{};
        /// One-way shutdown gate.
        bool closed{};
        /// Actual worker loops not yet finished, not cancellation count.
        std::atomic_uint workers{};
    };

    /// Drain accepted work outside the queue mutex, then publish worker completion with release ordering.
    static void run(Queue& queue);

    /// Workers hold no reference cycle back to the manager.
    std::shared_ptr<Queue> queue_ = std::make_shared<Queue>();
    /// Protects thread reclamation at the exit boundary only.
    std::mutex join_;
    /// Join even after completion; no detached threads may remain when unloading the library.
    std::array<std::thread, 2> threads_;
};
} // namespace comet::detail
