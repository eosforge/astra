// Leave the Windows allocator unchanged; Linux glibc residence evidence does not qualify another runtime.
#include "../memory.hpp"

namespace astra::memory {
bool prepare() noexcept {
    return true;
}
} // namespace astra::memory
