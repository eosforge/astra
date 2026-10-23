// Latch cooperative console cancellation; callbacks never borrow a Signals object.
#include "../signals.hpp"

#include <Windows.h>
#include <atomic>
#include <csignal>
#include <stdexcept>

namespace astra {
namespace {
/// Process-lifetime storage remains valid even while a handler is being removed.
std::atomic_bool stopped{false};
/// Reject overlapping owners instead of restoring another owner's handlers.
std::atomic_bool owned{false};
static_assert(std::atomic_bool::is_always_lock_free);

/// Handle console cancellation only; OS close/logoff deadlines are not a drain guarantee.
BOOL WINAPI control(DWORD event) noexcept {

    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) {
        return FALSE;
    }
    stopped.store(true, std::memory_order_relaxed);
    return TRUE;
}

/// Support a cooperative SIGTERM raised by this process's CRT.
void terminate(int) {
    stopped.store(true, std::memory_order_relaxed);
}
} // namespace

Signals::Signals() {

    if (owned.exchange(true, std::memory_order_acq_rel)) {
        throw std::logic_error("Process stop handlers already owned");
    }
    stopped.store(false, std::memory_order_relaxed);
    terminate_ = std::signal(SIGTERM, terminate);
    if (terminate_ == SIG_ERR) {
        owned.store(false, std::memory_order_release);
        throw std::runtime_error("Cannot install exit signal handler");
    }
    if (!SetConsoleCtrlHandler(control, TRUE)) {
        std::signal(SIGTERM, terminate_);
        owned.store(false, std::memory_order_release);
        throw std::runtime_error("Cannot install console stop handler");
    }
}

Signals::~Signals() {

    SetConsoleCtrlHandler(control, FALSE);
    std::signal(SIGTERM, terminate_);
    owned.store(false, std::memory_order_release);
}

bool Signals::requested() const noexcept {
    return stopped.load(std::memory_order_relaxed);
}
} // namespace astra
