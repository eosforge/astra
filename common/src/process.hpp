// Provide process stop ownership, cross-thread wakeups, and bounded Linux JSON diagnostics.
#pragma once
#include "signals.hpp"
#include <astra/policy.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

namespace astra {
/// Encode valid UTF-8 as a quoted JSON string, escaping control bytes, quotes, and backslashes.
/// The caller validates business identifiers; this function only encodes the supplied view.
std::string jsonString(std::string_view value);

/// Share notifications between Runtime and callbacks without borrowing Runtime itself.
/// A sequence change preserves notifications received while the control loop is processing work.
class Wakeup {
public:
    /// Capture the current notification sequence before stepping; pass it to the subsequent wait().
    std::uint64_t observe() const noexcept;

    /// Advance the sequence and notify a waiter without accessing Runtime or executing protocol work.
    void notify();

    /// Wait up to 10 ms for a sequence change so the caller can also poll stop and channel state.
    /// observed must have been captured before the current control-loop step.
    void wait(std::uint64_t observed);

private:
    /// Serialize sequence updates with the condition-variable check and transition to sleep.
    std::mutex mutex_;
    /// Block the control-loop waiter until notification or its polling deadline.
    std::condition_variable condition_;
    /// Notification counter, initially zero; a changed value means another step may have work.
    std::atomic_uint64_t sequence_{0};
};

/// Control-loop-owned Linux logger for fixed event names and validated fields, never credentials or remote error bodies.
/// Attempt nonblocking pipe/socket stdout writes and drop diagnostics on backpressure without retaining a queue.
class Logger {
public:
    /// Select the fixed component name from the role and attempt nonblocking stdout configuration.
    /// Preserve existing descriptor flags when stdout is a pipe or socket; O_NONBLOCK setup is best effort.
    explicit Logger(Member::Role role);
    /// Accept a fixed process-entry component name, such as pulsar, never unchecked remote text.
    explicit Logger(std::string_view component);

    /// Restore captured stdout flags without closing the process's standard-output descriptor.
    ~Logger();

    /// Keep stdout flag restoration under a single owner.
    Logger(const Logger&) = delete;

    /// Prevent replacement of the logger owner and its saved stdout state.
    Logger& operator=(const Logger&) = delete;

    /// Attempt one diagnostic write of at most 4096 bytes; ignore write failure without buffering or retry.
    /// event must be fixed and safe; fields must be a validated JSON object, defaulting to {} and not escaped here.
    void write(std::string_view event, std::string_view fields = "{}") const;

    /// Encode the connection snapshot and local node ID as public diagnostics without reading secrets or mutating policy.
    void status(const Policy::State& status, const Id& id) const;

    /// Write a fixed event with a reason selected only from Status::name(error), never untrusted remote error text.
    void failure(std::string_view event, Status::Code error) const;

private:
    /// Fixed component name, normally selected from Member::Role, such as star or planet.
    std::string component_;
    /// Original stdout flags for restoration; -1 means flags were not captured or stdout is not a pipe/socket.
    int flags_ = -1;
};
} // namespace astra
