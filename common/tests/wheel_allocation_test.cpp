// Verify allocation-free wheel lifetimes in an isolated process; diagnostics run outside the measured interval.
#include "check.hpp"
#include "wheel.hpp"

#include <cstdio>
#include <cstdlib>
#include <new>

namespace {
/// Process-wide single-thread allocation count; compare measured deltas without runtime-startup assumptions.
std::size_t allocations{};

/// Allocates size with normal alignment when alignment is zero, otherwise POSIX alignment, preserving new_handler semantics.
[[gnu::noinline]] void* allocate(std::size_t size, std::size_t alignment = 0) {

    for (;;) {
        // Allocation result; zero size still requires an independent releasable address.
        void* address = nullptr;
        if (alignment == 0) {
            address = std::malloc(size == 0 ? 1 : size);
        } else if (posix_memalign(&address, alignment, size == 0 ? 1 : size) != 0) {
            address = nullptr;
        }
        if (address != nullptr) {
            ++allocations;
            return address;
        }
        if (auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

/// Releases replacement-new storage through a separate function to avoid optimizer mismatch diagnostics.
[[gnu::noinline]] void release(void* address) noexcept {
    std::free(address);
}
} // namespace

/// Normally aligned scalar allocation.
void* operator new(std::size_t size) {
    return allocate(size);
}

/// Normally aligned array allocation shares the scalar count.
void* operator new[](std::size_t size) {
    return allocate(size);
}

/// Over-aligned scalar allocation prevents hidden aligned new from bypassing measurement.
void* operator new(std::size_t size, std::align_val_t alignment) {
    return allocate(size, static_cast<std::size_t>(alignment));
}

/// Over-aligned array allocation shares the scalar allocation domain.
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return allocate(size, static_cast<std::size_t>(alignment));
}

/// All delete variants share one domain; size/alignment do not alter POSIX release.
void operator delete(void* address) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* address) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* address, std::size_t) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* address, std::size_t) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* address, std::align_val_t) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* address, std::align_val_t) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete(void* address, std::size_t, std::align_val_t) noexcept {
    release(address);
}

/// Replacement deallocation entry; null is valid and size/alignment do not change the allocation domain.
void operator delete[](void* address, std::size_t, std::align_val_t) noexcept {
    release(address);
}

namespace {
/// First verifies the counter observes new, then measures stack-owned schedule/cancel/expiry/rescheduling; nonzero fails CTest.
template <typename W>
bool checkAllocation(const char* name) {

    // Calibration baseline/control prevents a broken counter from reporting false zero.
    const auto baseline = allocations;
    void* control = ::operator new(1);
    ::operator delete(control);
    if (allocations != baseline + 1) {
        return false;
    }

    // Read before construction and after destruction to include the entire Wheel/Node lifetime.
    const auto before = allocations;
    // Initially true; accumulates schedule results without allocating failure diagnostics inside measurement.
    bool valid = true;
    // Callback count, initially zero; expect exactly two per node.
    std::size_t expired = 0;
    {
        // Template-configured zero-origin wheel, with full lifetime measured.
        W wheel;
        // 1024 stack Nodes with stable addresses, never moved by container growth.
        std::array<typename W::Node, 1024> nodes;
        // Node index selects delay id + 1.
        for (std::size_t id = 0; id < nodes.size(); ++id) {
            valid &= wheel.schedule(nodes[id], id + 1);
            W::cancel(nodes[id]);
            valid &= wheel.schedule(nodes[id], id + 1);
        }

        // First expiry reschedules every Node by one tick, also checking callback-path allocations.
        std::array<bool, 1024> rescheduled{};
        // 2048 advancement ticks cover initial expiry plus one self-reschedule.
        for (std::size_t step = 0; step < 2048; ++step) {
            wheel.tick([&](auto* node) noexcept {
                ++expired;
                // Stable array address yields node index; each reschedules itself once.
                const auto id = static_cast<std::size_t>(node - nodes.data());
                if (!rescheduled[id]) {
                    valid &= wheel.schedule(*node, 1);
                    rescheduled[id] = true;
                }
            });
        }
        valid &= expired == 2 * nodes.size();
        // Borrows stable stack hooks to verify rescheduling after unlink.
        for (auto& node : nodes) {
            valid &= !node.scheduled();
            valid &= wheel.schedule(node, 65'536);
        }
    }

    // Post-destruction counter includes cleanup within the measured window.
    const auto after = allocations;
    std::printf("%s: %zu allocations, %zu callbacks, Node=%zu bytes, Wheel=%zu bytes\n", name, after - before, expired, sizeof(typename W::Node), sizeof(W));
    return valid && after == before;
}

} // namespace

// Report both independently calibrated configurations through the native assertion collector.
int main() {

    // Complete default five-level, 256-slot lifecycle.
    const bool basic = checkAllocation<astra::Wheel<>>("Wheel<5,8>");
    // Store's four-level, 1024-slot configuration.
    const bool store = checkAllocation<astra::Wheel<4, 10>>("Wheel<4,10>");
    // Count completed checks only after the allocation windows close, preserving the measured allocator behavior.
    CHECK(basic);
    CHECK(store);
    return basic && store ? 0 : 1;
}
