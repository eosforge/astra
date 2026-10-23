// Keep mesh task threads resident so fixture churn does not contaminate resource observations.
#pragma once

#include <condition_variable>
#include <cstddef>
#include <exception>
#include <functional>
#include <mutex>
#include <stop_token>
#include <thread>
#include <vector>

namespace comet::test {
/// Run one operation per fixed worker; the caller owns every borrowed input until run returns.
class Batch {
public:
    /// Construct 1..96 workers; partially constructed workers stop before their shared state is destroyed.
    explicit Batch(std::size_t count);

    /// Admit one bounded round and drain all callbacks before propagating its first exception.
    void run(std::function<void(std::size_t)> task);

private:
    /// Consume each admitted generation once, invoking user code outside the shared-state lock.
    void work(std::stop_token stop, std::size_t index);

    /// Protect admission, generation and completion state.
    std::mutex mutex_;
    /// Stop-aware idle wait, including partial construction cleanup.
    std::condition_variable_any ready_;
    /// Notify the caller only after all callbacks have returned.
    std::condition_variable done_;
    /// Immutable during one round; captures borrow caller-owned inputs.
    std::function<void(std::size_t)> task_;
    /// First callback exception, propagated after the round drains.
    std::exception_ptr failure_;
    /// Number of admitted callbacks not yet retired.
    std::size_t pending_{};
    /// Retain admission through caller retirement, including the last-worker notification window.
    bool active_{};
    /// Alternating phase; another round starts only after complete retirement.
    bool generation_{};
    /// Destroy first so shared state outlives every worker.
    std::vector<std::jthread> workers_;
};
} // namespace comet::test
