// Read and qualify the host physical-clock reference for calibrated Pulsar time.
#pragma once
#include <astra/clock.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>

namespace astra {
/// Converts a system-disciplined physical reference into a continuous Unix-epoch clock.
class Source {
public:
    /// Reads CLOCK_REALTIME and adjtimex without changing the system clock or managing time daemons.
    /// Unsynchronized state, excessive error, or kernel query failure yields no sample. BOOTTIME failure throws.
    static std::optional<Clock::Estimate> sample();

    /// Called on one worker thread and must return in bounded time. Defaults to read-only kernel sampling; tests may inject faults or restarts.
    using Provider = std::function<std::optional<Clock::Estimate>()>;
    /// Owns provider and starts one sampling thread; an empty callback throws invalid_argument. Dependencies must outlive the thread.
    explicit Source(Provider provider = sample);
    /// Stops and joins; every RPC borrowing this object must exit first.
    ~Source();

    /// Keep one owner of physical-clock sampling worker; copying is forbidden.
    Source(const Source&) = delete;

    /// Keep one owner of physical-clock sampling worker; copying is forbidden.
    Source& operator=(const Source&) = delete;
    /// Returns continuous time and quality without querying system synchronization. Uninitialized or failed clocks yield no reading.
    std::optional<Clock::Reading> now() const;
    /// Measured BOOTTIME rho in nanoseconds; zero until calibration. Acquire pairs with worker publication.
    std::uint64_t precision() const noexcept;

private:
    /// Failure revokes qualification and retries next second; temporary reference loss preserves the correction anchor.
    void run(std::stop_token stop) noexcept;
    /// Used only by the sampling thread, without per-RPC subprocesses or disk reads.
    Provider provider_;
    /// Pulsar permits at most 500 ppm additional slew; Star retains more catch-up capacity.
    Clock clock_{500};
    /// Published only by the calibration thread; RPCs only read it.
    std::atomic_uint64_t precision_{};
    /// Cancellable one-second sampling wait.
    std::mutex waitMutex_;

    /// Wake the sampling worker for its next deadline or stop request under the associated mutex.
    std::condition_variable_any condition_;
    /// Constructed last and stopped first; cannot outlive provider_ or clock_.
    std::jthread worker_;
};
} // namespace astra
