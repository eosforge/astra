// Measure native source restoration and recovery resource behavior.
#include "catalog_state.hpp"
#include "measure.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
/// Measure cross-source high-watermark merging using the production state model.
using State = astra::Catalog::State;

/// Fix qualified business time to isolate Pulsar, actual expiry and network effects; this is not system throughput.
auto reading() {
    return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true});
}

/// Run six local writers alongside complete recovery of two remote sources; scopes controls atomic recovery size for the same record count.
void run(std::size_t records, std::size_t scopes, bool concurrent) {

    State target(reading, {}); // All three sources share the real committer and default logical memory budgets.
    const auto body = std::make_shared<const astra::Catalog::Buffer>(128, 1);
    const auto alternate = std::make_shared<const astra::Catalog::Buffer>(128, 2); // Alternate payloads to prevent unchanged-content shortcuts.
    std::vector<astra::Scope> addresses;                                           // Prepare a fixed address for every remote Scope outside write timing.
    for (std::size_t index = 0; index < scopes; ++index) {
        addresses.push_back({"remote", std::to_string(index)});
    }
    const astra::Scope local{"local", "writers"}; // SDK and remote scopes differ but may contend on existing domain locks.
    std::array<std::string, 6> keys;              // Each writer owns its key and business version, without conflict retries.
    for (std::size_t index = 0; index < keys.size(); ++index) {
        keys[index] = "writer-" + std::to_string(index);
        Measure::require(target.publish(local, keys[index], body, 1, 600000).has_value());
    }
    std::array<std::string, 2> sources{"remote-a", "remote-b"};
    for (const auto& source : sources) {
        Measure::require(target.admit(source).has_value());
    }

    constexpr std::size_t operations = 10000;            // Use fixed work per writer; failure must not shorten the denominator and still report success.
    std::array<std::vector<std::int64_t>, 6> samples;    // Workers own separate sample arrays; aggregate after all have exited.
    std::array<Measure::Clock::time_point, 6> completed; // Record each writer's finish time without including the tail spent waiting for recovery workers.
    std::array<std::vector<std::int64_t>, 2> recovery;   // Full recovery duration includes private Draft construction and installation.
    std::atomic_bool failed{};                           // Capture thread exceptions and report scenario failure instead of letting them escape into terminate.
    std::barrier barrier(9);                             // Six writers, two recovery workers and the coordinator share one start barrier.
    std::vector<std::jthread> workers;                   // Join all owned workers on both normal and exceptional exit.

    /// Release missing barrier participants on partial thread startup so existing workers can join.
    struct Launch {
        /// Borrow the common start barrier so failed partial startup can drop missing participants.
        std::barrier<>& barrier;
        /// Borrow the worker collection to count successfully created participants before rollback.
        std::vector<std::jthread>& workers;
        /// True after the coordinator released the normal start gate; false requires startup rollback.
        bool started{};

        ~Launch() {
            if (!started) {
                for (auto missing = workers.size(); missing < 9; ++missing) {
                    barrier.arrive_and_drop(); // If thread creation fails, release existing barrier participants before joining.
                }
            }
        }
    } launch{barrier, workers}; // Destroy this guard before workers so resource refusal cannot strand threads at the start barrier.

    workers.reserve(8);
    for (auto& values : samples) {
        values.resize(operations);
    }
    for (auto& values : recovery) {
        values.reserve(16);
    }
    for (std::size_t index = 0; index < samples.size(); ++index) {
        workers.emplace_back([&, index] {
            barrier.arrive_and_wait();
            try {
                for (std::size_t operation = 0; operation < operations; ++operation) {
                    const auto start = Measure::Clock::now(); // Include real commit-lock waits and native/visible projection commits.
                    Measure::require(target.publish(local, keys[index], operation % 2 ? body : alternate, operation + 2, 600000).has_value());
                    samples[index][operation] = std::chrono::duration_cast<std::chrono::nanoseconds>(Measure::Clock::now() - start).count();
                }
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
            completed[index] = Measure::Clock::now();
        });
    }
    for (std::size_t index = 0; index < sources.size(); ++index) {
        workers.emplace_back([&, index] {
            barrier.arrive_and_wait();
            try {
                for (std::uint64_t round = 1; concurrent && round <= 16; ++round) {
                    const auto start = Measure::Clock::now(); // Measure full recovery, not constant-time snapshot capture.
                    auto draft = target.prepare(sources[index], round);
                    Measure::require(draft.has_value());
                    for (std::size_t record = 0; record < records; ++record) {
                        Measure::require(draft->set(addresses[record % scopes], sources[index] + "-" + std::to_string(record), {round, round % 2 ? body : alternate, astra::Clock::Time(600s)}).has_value());
                    }
                    Measure::require(target.replace(sources[index], std::move(*draft)).has_value());
                    recovery[index].push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Measure::Clock::now() - start).count());
                }
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
        });
    }
    const auto start = Measure::Clock::now(); // Publish the start timestamp before releasing the barrier.
    launch.started = true;
    barrier.arrive_and_wait();
    workers.clear();
    Measure::require(!failed.load(std::memory_order_relaxed));

    std::vector<std::int64_t> writes; // Merge samples only after timing ends.
    writes.reserve(operations * samples.size());
    for (auto& values : samples) {
        writes.insert(writes.end(), values.begin(), values.end());
    }
    const auto seconds = std::chrono::duration<double>(*std::ranges::max_element(completed) - start).count();
    Measure::report(concurrent ? "catalog.writes_during_recovery" : "catalog.concurrent_writes", std::move(writes), seconds, operations * samples.size());
    for (std::size_t index = 0; index < recovery.size(); ++index) {
        if (concurrent) {
            Measure::report(sources[index], std::move(recovery[index]), std::chrono::duration<double>(Measure::Clock::now() - start).count(), 16);
        }
    }
    for (const auto& key : keys) {
        const auto point = target.find(local, key); // Validate query success before dereferencing its result.
        Measure::require(point.has_value() && point->record && point->record->version == operations + 1);
    }
    for (const auto& source : sources) {
        Measure::require(target.received(source) == (concurrent ? 16 : 0));
    }
}
} // namespace

/// Use existing tools/artifacts only; arguments select remote record count, scope count and recovery, without starting network services.
int main(int count, char** arguments) {
    try {
        Measure::require(count == 4);
        const auto records = Measure::number(arguments[1], 1, 10000), scopes = Measure::number(arguments[2], 1, 128);
        Measure::require(records >= scopes && records % scopes == 0);
        run(records, scopes, Measure::number(arguments[3], 0, 1) != 0);
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
