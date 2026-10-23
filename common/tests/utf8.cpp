// Implement the independent RFC 3629 test encoder.
#include "utf8.hpp"

namespace astra::test {
std::string encoded(std::uint32_t value) {
    if (value < 0x80) {
        return std::string(1, static_cast<char>(value));
    }

    // Scalar magnitude selects the encoding width; continuation groups are emitted in reverse order.
    const unsigned width = value < 0x800 ? 2 : value < 0x10000 ? 3
                                                               : 4;
    constexpr std::array<unsigned, 3> prefixes{0xc0, 0xe0, 0xf0};
    std::string result(width, '\0');
    for (unsigned position = width - 1; position != 0; --position) {
        result[position] = static_cast<char>(0x80 | (value & 0x3f));
        value >>= 6;
    }
    result[0] = static_cast<char>(prefixes[width - 2] | value);
    return result;
}
} // namespace astra::test
