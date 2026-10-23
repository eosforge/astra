// Preserve getrandom's short-read and interruption handling on Linux.
#include "../random.hpp"

#include <cerrno>
#include <sys/random.h>
#include <system_error>

namespace astra {
void random(std::span<std::uint8_t> bytes) {

    // Consume only confirmed bytes; interrupted reads make no progress.
    while (!bytes.empty()) {
        const auto count = ::getrandom(bytes.data(), bytes.size(), 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::system_error(count < 0 ? errno : EIO, std::generic_category(), "Identity random source failed");
        }
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
}
} // namespace astra
