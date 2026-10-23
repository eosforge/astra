// Verify actual glibc arena expansion under simultaneous held allocations after the production Star startup policy.
#include "check.hpp"
#include "memory.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <latch>
#include <malloc.h>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
/// Release allocating workers on success, observation failure or partial thread creation before shared latches are destroyed.
class Workers {
public:
    /// Keep every completed worker allocation live until the owner finishes observing native heaps.
    Workers() {

        workers_.reserve(32);
        try {
            for (unsigned index = 0; index < 32; ++index) {
                workers_.emplace_back([this] {
                    std::array<std::unique_ptr<std::byte[]>, 32> held; // Each worker touches and retains two MiB of sub-mmap-threshold blocks.
                    for (auto& block : held) {
                        block = std::make_unique<std::byte[]>(64 * 1024);
                    }
                    ready_.count_down();
                    release_.wait();
                });
            }
        } catch (...) {
            release_.count_down();
            workers_.clear();
            throw;
        }
    }

    /// Unblock and join all created workers before either latch leaves its lifetime.
    ~Workers() {
        release_.count_down();
        workers_.clear();
    }

    /// Observe only after all thirty-two workers retain their complete allocation sets.
    void wait() {
        ready_.wait();
    }

private:
    /// Signals complete allocation exposure; workers never wait on a partially constructed group.
    std::latch ready_{32};
    /// Keeps allocations live until observation completes or the owning scope unwinds.
    std::latch release_{1};
    /// Owns every actual thread rather than detached or fire-and-forget work.
    std::vector<std::jthread> workers_;
};

/// Count the actual allocator heaps while every worker retains its allocations; never infer the bound from mallopt's return value.
std::size_t arenas() {

    const std::unique_ptr<std::FILE, int (*)(std::FILE*)> file(std::tmpfile(), &std::fclose);
    CHECK(file && ::malloc_info(0, file.get()) == 0 && std::fflush(file.get()) == 0 && std::fseek(file.get(), 0, SEEK_SET) == 0);
    std::string text; // The independently read native XML has a fixed one-MiB collection ceiling.
    std::array<char, 4096> buffer{};
    while (const auto count = std::fread(buffer.data(), 1, buffer.size(), file.get())) {
        text.append(buffer.data(), count);
        CHECK(text.size() <= 1024 * 1024);
    }
    CHECK(!std::ferror(file.get()) && text.starts_with("<malloc version=") && text.ends_with("</malloc>\n"));

    std::size_t count{}, offset{};
    while ((offset = text.find("<heap nr=\"", offset)) != std::string::npos) {
        ++count;
        offset += 10;
    }
    CHECK(count > 0);
    return count;
}
} // namespace

/// Use enough live allocating threads to distinguish the new sixteen-arena default from the supported four-or-more-core libc default.
int main(int argc, char** argv) {
    try {

        CHECK(argc == 2 && std::thread::hardware_concurrency() >= 4);
        const std::string_view mode(argv[1]);
        CHECK(mode == "default" || mode == "environment" || mode == "tunables");
        const auto* environment = std::getenv("MALLOC_ARENA_MAX");
        const auto* tunables = std::getenv("GLIBC_TUNABLES");
        CHECK(mode != "default" || (!environment && !tunables));
        CHECK(mode != "environment" || (environment && std::string_view(environment) == "4" && !tunables));
        CHECK(mode != "tunables" || (!environment && tunables && std::string_view(tunables) == "glibc.malloc.arena_max=4"));
        CHECK(astra::memory::prepare());

        std::size_t count{}; // Observation exceptions still release the owning worker group.
        {
            Workers workers;
            workers.wait();
            count = arenas();
        }
        CHECK(count <= (mode == "default" ? 16 : 4));
        std::cout << "STAR-MEMORY " << mode << " arenas=" << count << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
