// Own Linux stop signals and restore their previous dispositions.
#include "../signals.hpp"

#include <atomic>
#include <stdexcept>

namespace astra {
namespace {
/// Process-lifetime latch accessed only with lock-free atomic operations.
std::atomic_bool stop_requested{false};
static_assert(std::atomic_bool::is_always_lock_free);

/// Signal context only sets the latch; the control loop owns draining.
void stopSignal(int) {
    stop_requested.store(true, std::memory_order_relaxed);
}
} // namespace

Signals::Signals() {

    stop_requested.store(false, std::memory_order_relaxed);
    struct sigaction action{};
    action.sa_handler = stopSignal;
    sigemptyset(&action.sa_mask);

    if (sigaction(SIGINT, &action, &interrupt_)) {
        throw std::runtime_error("Cannot install exit signal handlers");
    }

    // Roll back each successfully installed handler if later installation fails.
    if (sigaction(SIGTERM, &action, &terminate_)) {
        sigaction(SIGINT, &interrupt_, nullptr);
        throw std::runtime_error("Cannot install exit signal handlers");
    }

    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, &pipe_)) {
        sigaction(SIGINT, &interrupt_, nullptr);
        sigaction(SIGTERM, &terminate_, nullptr);
        throw std::runtime_error("Cannot install pipe signal handler");
    }
}

Signals::~Signals() {

    sigaction(SIGINT, &interrupt_, nullptr);
    sigaction(SIGTERM, &terminate_, nullptr);
    sigaction(SIGPIPE, &pipe_, nullptr);
}

bool Signals::requested() const noexcept {
    return stop_requested.load(std::memory_order_relaxed);
}

} // namespace astra
