// Use Windows CNG without persistent provider handles or a fallback entropy source.
#include "../random.hpp"

#include <Windows.h>
#include <algorithm>
#include <bcrypt.h>
#include <limits>
#include <stdexcept>

namespace astra {
void random(std::span<std::uint8_t> bytes) {

    while (!bytes.empty()) {
        // BCrypt takes a 32-bit byte count even in a 64-bit process.
        const auto count = static_cast<ULONG>(std::min(bytes.size(), static_cast<std::size_t>(std::numeric_limits<ULONG>::max())));
        if (BCryptGenRandom(nullptr, bytes.data(), count, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            throw std::runtime_error("Identity random source failed");
        }
        bytes = bytes.subspan(count);
    }
}
} // namespace astra
