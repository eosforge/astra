// Verify sampling queue capacity, close rejection, and complete worker draining.
#include "check.hpp"
#include "sampling.hpp"

#include <atomic>
#include <chrono>
#include <exception>
#include <future>
#include <iostream>
#include <thread>

namespace {
using namespace std::chrono_literals;

/// Queue stays bounded while every worker is occupied; shutdown rejects new tasks but drains accepted cleanup responsibilities.
void bounded() {

    std::promise<void> exit; // Main thread releases workers on success or assertion failure.
    auto ready = exit.get_future().share();
    std::atomic_uint entered{}, completed{}; // Actual start and finish counts, without fixed-sleep inference about queue state.
    auto sampling = comet::detail::Sampling::open();

    /// Unblock queued work before the sampling manager joins its workers.
    struct Release {
        /// Destroyed before the thread manager to avoid self-wait on failure.
        std::promise<void>* exit;

        ~Release() {
            if (exit) {
                exit->set_value();
            }
        }
    } release{&exit};

    for (unsigned index = 0; index < 2; ++index) { // Both workers enter blocking tasks first.
        CHECK(sampling->submit([&] { ++entered; ready.wait(); ++completed; }));
    }
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (entered.load() != 2) {
        CHECK(std::chrono::steady_clock::now() < deadline);
        std::this_thread::sleep_for(1ms);
    }
    for (unsigned index = 0; index < 64; ++index) { // Fixed slots for candidates not yet executed.
        CHECK(sampling->submit([&] { ++completed; }));
    }
    CHECK(!sampling->submit([&] { ++completed; }));
    sampling->close();
    sampling->close(); // Idempotent stop preserves accepted tasks and actual worker counts.
    CHECK(!sampling->finished() && !sampling->submit([&] { ++completed; }));
    exit.set_value();
    release.exit = nullptr;
    sampling->wait();
    sampling->wait(); // Multiple sequential waiters are safe too.
    CHECK(sampling->finished() && completed.load() == 66);
}
} // namespace

/// Standalone SDK verifies queue bounds and actual thread reclamation on Linux and Windows.
int main() {
    try {
        bounded();
        std::cout << "Sampling lifecycle cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
