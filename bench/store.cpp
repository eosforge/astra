// Finite microbenchmarks for Store delta extraction, writes and snapshots without services.
// Comparisons use identical compilers, arguments and this driver, linked separately against each Store revision.
#include "store.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <string_view>

using namespace astra;

/// Run seven rounds of iterations operations and report median per-call time plus an observable checksum.
/// Operation returns an integer digest; preparation is untimed and single-thread results do not measure contention throughput.
void measure(std::string_view name, std::size_t iterations, auto&& operation) {
    // Sort seven ns/op samples to reduce incidental scheduling noise.
    std::array<double, 7> samples{};
    // Consume actual query results to prevent an optimized-away empty loop.
    std::uint64_t checksum = 0;

    for (auto& sample : samples) {

        const auto started = Steady::now();

        for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
            checksum += operation();
        }
        sample = std::chrono::duration<double, std::nano>(Steady::now() - started).count() / static_cast<double>(iterations);
    }
    std::ranges::sort(samples);
    std::cout << "{\"case\":\"" << name << "\",\"median_ns\":" << samples[samples.size() / 2] << ",\"iterations\":" << iterations
              << ",\"checksum\":" << checksum << "}\n";
}

/// Exclude preparation, output and Store destruction from per-call timing.
int main() {
    // Vary retained history size and short versus heap-allocated keys.
    for (const std::uint64_t batches : {64U, 1000U}) {
        for (const std::size_t keySize : {8U, 128U}) {
            // Overwrite one key throughout history so extraction comparisons do not vary current Map size.
            Store store(static_cast<std::size_t>(batches));
            // Prepare equal-length keys and one-byte payloads before timing for every revision.
            const std::string key(keySize, 'k');

            for (std::uint64_t version = 1; version <= batches; ++version) {
                store.put(key, {1});
            }
            // Cover near-current, slightly behind and full-window replay.
            for (const auto missing : {std::uint64_t{1}, std::uint64_t{16}, batches}) {
                // Scale iteration count by result size to keep large-window copies finite.
                const auto iterations = std::clamp<std::size_t>(100000 / static_cast<std::size_t>(missing), 50, 10000);

                const auto name = "delta/b" + std::to_string(batches) + "/k" + std::to_string(keySize) + "/d" + std::to_string(missing);
                measure(name, iterations, [&] {
                    // Consume both version and record count; destroy the result inside the timed call.
                    const auto result = store.extract(batches - missing);
                    return result.version + result.deltas.size();
                });
            }
        }
    }
    // Keep the live Map small while comparing overwrite, delete/recreate and history-eviction costs.
    Store writes;
    measure("write/overwrite", 10000, [&] {
        writes.put("key", {1});
        return writes.version();
    });
    measure("write/remove-recreate", 10000, [&] {
        writes.remove("key");
        writes.put("key", {1});
        return writes.version();
    });
    // Compare live and mostly deleted snapshots to exercise exact-count accounting.
    for (const unsigned deleted : {0U, 900U}) {
        // Retain enough history to preserve empty nodes across all seven rounds.
        Store snapshots(10000);

        for (unsigned index = 0; index < 1000; ++index) {
            snapshots.put(std::to_string(index), {1});
        }
        for (unsigned index = 0; index < deleted; ++index) {
            snapshots.remove(std::to_string(index));
        }
        measure("snapshot/deleted" + std::to_string(deleted), 300, [&] {
            snapshots.put("live", {1});
            return snapshots.snapshot()->data.size();
        });
    }
}
