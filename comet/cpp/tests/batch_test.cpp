// Verify resident mesh workers, callback ownership, exception draining and repeated admission.
#include "batch.hpp"
#include "check.hpp"

#include <array>
#include <barrier>
#include <iostream>
#include <set>

/// Exercise public fixture behavior without networking or timing-dependent success assertions.
int main() {
    try {
        for (const auto count : {0U, 97U}) {
            bool refused = false; // Invalid capacity must fail before creating any worker.
            try {
                comet::test::Batch invalid(count);
            } catch (const std::invalid_argument&) {
                refused = true;
            }
            CHECK(refused);
        }
        comet::test::Batch batch(6);
        std::array<std::thread::id, 6> identities;
        std::array<std::size_t, 6> visits{};
        std::barrier together(6); // Every callback must be admitted concurrently, rather than serialized by the pool lock.
        batch.run([&](std::size_t index) {
            identities[index] = std::this_thread::get_id();
            together.arrive_and_wait();
            ++visits[index];
        });
        CHECK(std::set(identities.begin(), identities.end()).size() == 6);
        for (std::size_t round = 0; round < 128; ++round) {
            batch.run([&](std::size_t index) {
                CHECK(std::this_thread::get_id() == identities[index]);
                CHECK(visits[index] == round + 1);
                ++visits[index];
            });
        }
        bool failed = false; // Callback errors may propagate only after the other five operations have retired.
        try {
            batch.run([&](std::size_t index) {
                ++visits[index];
                together.arrive_and_wait();
                if (index == 0) {
                    throw std::runtime_error("mesh callback witness");
                }
            });
        } catch (const std::runtime_error& error) {
            failed = std::string_view(error.what()) == "mesh callback witness";
        }
        CHECK(failed);
        for (const auto count : visits) {
            CHECK(count == 130);
        }
        batch.run([&](std::size_t index) {
            CHECK(std::this_thread::get_id() == identities[index]);
            bool refused = false; // A worker must receive an error, not deadlock by recursively starting a round.
            try {
                batch.run([](std::size_t) {});
            } catch (const std::logic_error&) {
                refused = true;
            }
            CHECK(refused);
        });
        bool refused = false;
        try {
            batch.run({});
        } catch (const std::logic_error&) {
            refused = true;
        }
        CHECK(refused);
        {
            comet::test::Batch full(96);
            std::array<std::thread::id, 96> threads;
            full.run([&](std::size_t index) { threads[index] = std::this_thread::get_id(); });
            CHECK(std::set(threads.begin(), threads.end()).size() == 96);
        }
        // Destruction with idle workers must stop and join them without another admitted round.
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
