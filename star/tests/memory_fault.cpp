// Reject only the expected allocator startup call in an isolated real-Star subprocess; never ship this interposer.
#include <cstdio>
#include <malloc.h>

/// Make the real process entry observe libc rejection, or diagnose an unexpected interposed call rather than accepting it silently.
extern "C" int mallopt(int option, int value) noexcept {
    if (option == M_ARENA_MAX && value == 16) {
        std::fputs("STAR-MEMORY-REJECT arena=16\n", stderr);
    } else {
        std::fprintf(stderr, "STAR-MEMORY-UNEXPECTED option=%d value=%d\n", option, value);
    }
    return 0;
}
