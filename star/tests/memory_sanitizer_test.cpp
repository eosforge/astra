// Keep the instrumentation allocator independent from glibc arena tuning, including native tuning rejection.
#include "check.hpp"
#include "memory.hpp"

#include <cstdlib>
#include <iostream>

#if !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
#error This fixture requires the actual instrumentation allocator.
#endif

namespace {
int calls{};

/// Require startup to accept its instrumentation allocator without consulting libc tuning or operator overrides.
void check(const char* arena, const char* tunables) {

    CHECK(::unsetenv("MALLOC_ARENA_MAX") == 0 && ::unsetenv("GLIBC_TUNABLES") == 0);
    if (arena) {
        CHECK(::setenv("MALLOC_ARENA_MAX", arena, 1) == 0);
    }
    if (tunables) {
        CHECK(::setenv("GLIBC_TUNABLES", tunables, 1) == 0);
    }

    calls = 0;
    CHECK(astra::memory::prepare());
    CHECK(calls == 0);
}
} // namespace

/// Reject any attempted glibc tuning, without replacing allocation or suppressing a Sanitizer diagnostic.
extern "C" int __wrap_mallopt(int, int) noexcept {
    ++calls;
    return 0;
}

/// Exercise the absent setting and both operator overrides against the real production adapter.
int main() {
    try {

        check(nullptr, nullptr);
        check("4", nullptr);
        check(nullptr, "glibc.malloc.arena_max=4");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
