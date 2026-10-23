// Encode allocation-fault observation keys independently of native state transitions.
#include "allocation.hpp"

namespace astra::test::allocation {
void key(std::ostream& output, std::string_view value) {
    constexpr std::string_view digits = "0123456789abcdef";
    output << '"';
    for (const char item : value) {
        const auto byte = static_cast<unsigned char>(item); // Preserve signed-char bits without narrowing implicitly.
        output << digits[byte >> 4] << digits[byte & 15];
    }
    output << '"';
}
} // namespace astra::test::allocation
