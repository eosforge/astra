// Coordinate delivery observations and accounting for explicit network benchmarks.
#pragma once
#include <comet/observer.hpp>
#include <comet/subscriber.hpp>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// Each writer has a confirmation slot; callbacks look up only hot keys to avoid polling one SDK lock from every writer.
class Delivery {
    /// One hot key's writer wait state and per-subscription confirmation positions.
    struct Slot {
        /// Protects seen and the writer's wait/notification boundary.
        std::mutex gate;
        /// Wake only the writer for this key.
        std::condition_variable changed;
        /// Installed sequence per subscription, initially zero and protected by gate.
        std::vector<std::uint64_t> seen;
    };

public:
    /// Own all key names; the first writers entries are hot, while others verify initial record count.
    Delivery(std::vector<std::string> keys, std::size_t writers, std::size_t watchers, std::size_t bytes, std::size_t attr);

    /// Inspect hot keys only after receiving a complete Catalog View.
    void receive(std::size_t watcher, const comet::Subscriber::View& view);

    /// Ephemeris does not expose Data order; correlate by payload sequence and verify unchanged Attr size.
    void receive(std::size_t watcher, const comet::Observer::View& view);

    /// Application threads wait for the exact sequence at every subscription; callbacks never block on this wait. Invalid data or timeout fails the sample.
    void wait(std::size_t writer, std::uint64_t version);

private:
    /// Payload size is prevalidated; its sequence is a process-local probe correlation, not a new wire field.
    static std::uint64_t sequence(const std::vector<std::uint8_t>& bytes) noexcept;

    /// Use the same mutex for seen and its condition variable to avoid lost notifications and irrelevant key wakeups.
    void accept(std::size_t writer, std::size_t watcher, std::uint64_t version);

    /// Publish failure under every wait slot's synchronization boundary, including writers about to sleep.
    void fail();

    /// Owned stable lookup keys; the first writers_ entries are actively updated.
    const std::vector<std::string> keys_;
    /// 1..32 stable hot-key wait slots.
    const std::size_t writers_;
    /// At least 16 payload bytes, including the eight-byte sequence.
    const std::size_t bytes_;
    /// Expected Ephemeris attribute bytes; zero permits an empty attribute.
    const std::size_t attr_;
    /// Slot/mutex addresses remain stable and shared Delivery ownership extends callback lifetime.
    const std::unique_ptr<Slot[]> slots_;
    /// Payload failure is sticky; never discard it as a missing sample.
    std::atomic_bool failed_{};
};
