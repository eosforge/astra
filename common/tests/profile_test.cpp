// Produce controlled probe records for format, lifecycle, and feature-switch checks.
#include <astra/profile.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string_view>
#include <thread>
#include <vector>

namespace {
/// Same workload in enabled/disabled binaries; value is a local checksum independent of diagnostic records.
[[gnu::noinline]] std::uint64_t work(std::uint64_t value) {

    ASTRA_PROFILE_SCOPE("profile.test.work");
    {
        ASTRA_PROFILE_SCOPE("profile.test.child");
        // Fixed integer work; atomic signal fence prevents the compiler from removing the unobserved loop.
        for (unsigned step = 0; step != 16; ++step) {
            value = value * 6364136223846793005ULL + 1;
            std::atomic_signal_fence(std::memory_order_seq_cst);
        }
    }

    ASTRA_PROFILE_BEGIN(phase, "profile.test.phase");
    ASTRA_PROFILE_COUNT("profile.test.bytes", 17);
    ASTRA_PROFILE_END(phase);
    ASTRA_PROFILE_END(phase); // Early finish is idempotent; destructor adds no record.
    return value;
}

/// Exception unwinding restores the parent stack; later work remains a direct child of the same parent span.
void unwind() {

    ASTRA_PROFILE_SCOPE("profile.test.unwind");
    try {
        ASTRA_PROFILE_SCOPE("profile.test.throw");
        throw 7;
    } catch (int) {
        static_cast<void>(work(7));
    }
}
} // namespace

/// normal checks behavior, overflow checks file capacity, and bench measures probe overhead separately.
int main(int argc, char** argv) {

    if (argc != 2) {
        return 2;
    }
    const std::string_view mode(argv[1]); // Borrows command-line text without hot-path copying.
    if (mode != "normal" && mode != "overflow" && mode != "bench" && mode != "phase" && mode != "groups" && mode != "window") {
        return 2;
    }

    if (mode == "groups") {
        // Disabled core never enters the parent stack; clock samples independently, while enabling both retains valid nesting.
        ASTRA_PROFILE_SCOPE("common.runtime.profile_test.outer");
        {
            ASTRA_PROFILE_SCOPE("clock.test.sample");
            ASTRA_PROFILE_VALUE("clock.test.offset", -17);
            ASTRA_PROFILE_VALUE("clock.test.offset", 23);
            ASTRA_PROFILE_VALUE("clock.test.bound", std::numeric_limits<std::int64_t>::min());
            ASTRA_PROFILE_VALUE("clock.test.bound", std::numeric_limits<std::int64_t>::max());
        }
        {
            ASTRA_PROFILE_SCOPE("star.exchange.profile_test.receive");
            ASTRA_PROFILE_COUNT("star.exchange.profile_test.bytes", 4);
        }
        return 0;
    }

    if (mode == "window") {
        // Parent spanning collection expiry finishes normally; later children/counts stop without dangling parents or interrupting business work.
        ASTRA_PROFILE_SCOPE("clock.test.before");
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
        {
            ASTRA_PROFILE_SCOPE("clock.test.after");
            ASTRA_PROFILE_VALUE("clock.test.late", -1);
        }
        return 0;
    }

    if (mode == "phase") {
        // Models fixed Runtime work/wait alternation; random sampling must cover both classes rather than phase-locking away first.
        for (unsigned round = 0; round != 4096; ++round) {
            {
                ASTRA_PROFILE_SCOPE("profile.test.first");
            }
            {
                ASTRA_PROFILE_SCOPE("profile.test.second");
            }
        }
        return 0;
    }

    if (mode == "normal") {
        // Disabled builds neither evaluate arguments nor reference absent diagnostic variables.
        int evaluated{};
        {
            ASTRA_PROFILE_SCOPE("profile.test.arguments");
            ASTRA_PROFILE_COUNT("profile.test.argument", ++evaluated);
        }
#if !defined(ASTRA_PROFILE) || !ASTRA_PROFILE
        ASTRA_PROFILE_SCOPE(undefined_name);
        ASTRA_PROFILE_BEGIN(undefined_token, undefined_name);
        ASTRA_PROFILE_END(undefined_token);
        ASTRA_PROFILE_VALUE(undefined_name, ++evaluated);
        if (evaluated != 0) {
            return 3;
        }
#else
        if (evaluated != 1) {
            return 3;
        }
#endif
        // Thread join synchronizes mark with consume; no parent span moves across threads.
        ASTRA_PROFILE_STAMP(stamp);
        {
            ASTRA_PROFILE_SCOPE("profile.test.mark");
            ASTRA_PROFILE_MARK(stamp);
        }
        std::jthread consumer([&] { ASTRA_PROFILE_CONSUME(stamp, "profile.test.delay"); });
        consumer.join();
        ASTRA_PROFILE_CONSUME(stamp, "profile.test.delay"); // A consumed timestamp cannot be recorded twice.

        // Independent per-thread sampling and blocks; concurrent slots in one mapping cannot overlap.
        std::vector<std::jthread> workers;
        for (unsigned thread = 0; thread != 4; ++thread) {
            workers.emplace_back([] { for (unsigned round = 0; round != 20; ++round){ unwind();
} });
        }
        return 0; // workers join before destruction; parse mmap only after normal process exit.
    }

    // Loop excludes initialization; microbenchmark evidence does not replace actual three-Star throughput and tail-latency comparisons.
    std::uint64_t value = work(1);
    const auto count = mode == "bench" ? 1000000U : 30000U;
    const auto start = std::chrono::steady_clock::now();
    for (unsigned round = 0; round != count; ++round) {
        value = work(value);
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start).count();
    std::cout << "{\"calls\":" << count << ",\"elapsed_ns\":" << elapsed << ",\"checksum\":" << value << "}\n";
    return 0;
}
