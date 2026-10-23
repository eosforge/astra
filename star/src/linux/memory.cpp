// Bound default glibc arena expansion in Star without changing shared runtime or SDK allocation policy.
#include "../memory.hpp"

#include <cstdlib>
#include <string_view>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace astra::memory {
bool prepare() noexcept {

#if defined(__GLIBC__) && !defined(__SANITIZE_ADDRESS__) && !defined(__SANITIZE_THREAD__)
    if (const auto* value = std::getenv("MALLOC_ARENA_MAX"); value && *value) {
        return true; // The existing libc setting belongs to the operator; do not reinterpret its value.
    }
    if (const auto* value = std::getenv("GLIBC_TUNABLES")) {
        std::string_view remaining(value); // Borrow only during single-threaded process startup; never retain environment storage.
        while (!remaining.empty()) {
            const auto end = remaining.find(':');
            const auto item = remaining.substr(0, end);
            if (item.starts_with("glibc.malloc.arena_max=")) {
                return true;
            }
            if (end == std::string_view::npos) {
                break;
            }
            remaining.remove_prefix(end + 1);
        }
    }

    // Set before runNode creates gRPC/control threads; a later mallopt call may not update libc's cached arena limit.
    return ::mallopt(M_ARENA_MAX, 16) != 0;
#else
    return true; // Instrumentation and non-glibc allocators do not expose glibc arena tuning or its resource bound.
#endif
}
} // namespace astra::memory
