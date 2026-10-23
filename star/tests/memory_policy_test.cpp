// Verify allocator-policy branches independently from libc's heap expansion using the linker's mallopt boundary.
#include "check.hpp"
#include "memory.hpp"

#include <cstdlib>
#include <iostream>
#include <malloc.h>
#include <string_view>

namespace {
// Observe the exact option, value and call count without changing a real allocator or sharing state across processes.
int calls{}, option{}, value{}, result{};

/// Supply only the two documented allocator settings and verify whether policy applies its default or preserves the operator's choice.
void check(std::string_view name, const char* environment, const char* tunables, bool apply, bool success = true) {

    CHECK(::unsetenv("MALLOC_ARENA_MAX") == 0 && ::unsetenv("GLIBC_TUNABLES") == 0);
    if (environment) {
        CHECK(::setenv("MALLOC_ARENA_MAX", environment, 1) == 0);
    }
    if (tunables) {
        CHECK(::setenv("GLIBC_TUNABLES", tunables, 1) == 0);
    }

    calls = option = value = 0;
    result = success ? 1 : 0;
    CHECK(astra::memory::prepare() == (!apply || success));
    CHECK(calls == (apply ? 1 : 0));
    CHECK(!apply || (option == M_ARENA_MAX && value == 16));
    std::cout << "STAR-MEMORY-POLICY " << name << " calls=" << calls << " accepted=" << (!apply || success) << '\n';
}
} // namespace

/// Capture only the production adapter's libc call; the normal heap-count cases still use real mallopt.
extern "C" int __wrap_mallopt(int suppliedOption, int suppliedValue) noexcept {
    ++calls;
    option = suppliedOption;
    value = suppliedValue;
    return result;
}

/// Cover absence, native rejection and explicit settings without interpreting operator values as bounded-memory promises.
int main() {
    try {

        check("default", nullptr, nullptr, true);
        check("rejected", nullptr, nullptr, true, false);
        check("environment", "4", nullptr, false);
        check("environment-zero", "0", nullptr, false);
        check("environment-empty", "", nullptr, true);
        check("tunables", nullptr, "glibc.malloc.arena_max=4", false);
        check("tunables-first", nullptr, "glibc.malloc.arena_max=4:glibc.malloc.trim_threshold=65536", false);
        check("tunables-last", nullptr, "glibc.malloc.trim_threshold=65536:glibc.malloc.arena_max=4", false);
        check("tunables-empty-segment", nullptr, ":glibc.malloc.arena_max=4:", false);
        check("tunables-empty-value", nullptr, "glibc.malloc.arena_max=", false);
        check("tunables-other", nullptr, "glibc.malloc.trim_threshold=65536", true);
        check("tunables-similar", nullptr, "other.glibc.malloc.arena_max=4", true);
        check("tunables-empty", nullptr, "", true);
        check("tunables-trailing", nullptr, "glibc.malloc.trim_threshold=65536:", true);
        check("both", "4", "glibc.malloc.arena_max=8", false);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
