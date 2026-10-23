// Explicit measurement builds only. Counts process-wide replacement C++ new including static dependencies, excluding direct malloc and placement new.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <unistd.h>

namespace {
/// Successful allocation calls and cumulative requested bytes, initially zero; not live memory.
constinit std::atomic<unsigned long long> calls{}, bytes{};

/// Counts successful request sizes while preserving new_handler semantics, without allocating extra tracking objects.
void* allocate(std::size_t size, std::size_t alignment = 0) {

    for (;;) {
        // Owned allocation attempt; successful storage transfers to the caller for release.
        void* pointer = nullptr;
        if (alignment) {
            if (posix_memalign(&pointer, alignment, size ? size : 1) != 0) {
                pointer = nullptr;
            }
        } else {
            pointer = std::malloc(size ? size : 1);
        }
        if (pointer) {
            calls.fetch_add(1, std::memory_order_relaxed);
            bytes.fetch_add(size, std::memory_order_relaxed);
            return pointer;
        }

        // Runtime allocation-failure handler preserves standard new retry behavior.
        if (auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

/// atexit emits cumulative requests through this point, not live memory or peak RSS.
void report() {

    // Fixed stack output buffer; statistics output allocates no heap storage.
    char buffer[192];
    // snprintf required size; output only if the entire record fits.
    const int length = std::snprintf(buffer, sizeof(buffer), "{\"event\":\"allocation_measure\",\"calls\":%llu,\"requested_bytes\":%llu}\n", calls.load(std::memory_order_relaxed), bytes.load(std::memory_order_relaxed));
    if (length > 0 && static_cast<std::size_t>(length) < sizeof(buffer)) {
        // Best-effort output result; no retry or change to process status.
        const auto ignored = write(STDERR_FILENO, buffer, static_cast<std::size_t>(length));
        (void)ignored;
    }
}

/// Registers exit statistics once during static initialization, without a service thread.
[[maybe_unused]] const int registered = std::atexit(report);
} // namespace

/// Array/aligned overloads share one counting point; sized delete does not count again.
void* operator new(std::size_t size) {
    return allocate(size);
}

/// Replacement allocation entry; size is requested bytes and aligned overloads forward alignment to the same allocator.
void* operator new[](std::size_t size) {
    return allocate(size);
}

/// Replacement allocation entry; size is requested bytes and aligned overloads forward alignment to the same allocator.
void* operator new(std::size_t size, std::align_val_t alignment) {
    return allocate(size, static_cast<std::size_t>(alignment));
}

/// Replacement allocation entry; size is requested bytes and aligned overloads forward alignment to the same allocator.
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return allocate(size, static_cast<std::size_t>(alignment));
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* pointer) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* pointer) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* pointer, std::size_t) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* pointer, std::size_t) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* pointer, std::align_val_t) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* pointer, std::align_val_t) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* pointer, std::size_t, std::align_val_t) noexcept {
    std::free(pointer);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* pointer, std::size_t, std::align_val_t) noexcept {
    std::free(pointer);
}
