// Own process stop handlers without exposing platform state to runtime logic.
#pragma once
#ifndef _WIN32
#include <csignal>
#endif

namespace astra {
/// A process entry owns one handler set until its control loop has drained.
class Signals {
public:
    /// Install stop handlers or throw without leaving a partial installation.
    Signals();
    /// Restore handlers after workers have joined; never perform business shutdown here.
    ~Signals();
    /// Handler restoration belongs to one process-scope owner.
    Signals(const Signals&) = delete;
    /// Do not overwrite an active owner's saved handlers.
    Signals& operator=(const Signals&) = delete;
    /// Observe a latched request without clearing it or blocking.
    [[nodiscard]] bool requested() const noexcept;

private:
#ifdef _WIN32
    /// Preserve the CRT's previous SIGTERM handler for local termination requests.
    void (*terminate_)(int) = nullptr;
#else
    /// Preserve the process's previous interrupt, terminate and pipe handlers.
    struct sigaction interrupt_{};
    /// Restore the prior termination action when the owner leaves scope.
    struct sigaction terminate_{};
    /// Restore the prior broken-pipe action after all owned I/O has drained.
    struct sigaction pipe_{};
#endif
};
} // namespace astra
