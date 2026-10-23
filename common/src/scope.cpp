// Define scope ordering, encoding, and matching for domain selection.
#include <astra/scope.hpp>

#include <cstdint>

namespace astra {
bool Scope::valid() const noexcept {
    return text(sector, 128) && text(spectrum, 128);
}

bool Scope::internal() const noexcept {
    return sector.starts_with("__");
}

bool Scope::text(std::string_view value, std::size_t maximum) noexcept {

    if (value.empty() || value.size() > maximum) {
        return false;
    }

    // position advances by byte and first determines continuation count; reject overlong encodings, surrogates, and out-of-range Unicode.
    for (std::size_t position = 0; position < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[position++]);
        if (first == 0) {
            return false;
        }
        if (first < 0x80) {
            continue;
        }
        // following, minimum, and code track continuation count, minimum code point for this width, and accumulated decoding value.
        const unsigned following = first >= 0xc2 && first <= 0xdf ? 1U : first >= 0xe0 && first <= 0xef ? 2U
                                                                     : first >= 0xf0 && first <= 0xf4   ? 3U
                                                                                                        : 0U;
        const std::uint32_t minimum = following == 1 ? 0x80U : following == 2 ? 0x800U
                                                                              : 0x10000U;
        std::uint32_t code = following == 1 ? first & 0x1fU : following == 2 ? first & 0x0fU
                                                                             : first & 0x07U;
        if (following == 0 || following > value.size() - position) {
            return false;
        }
        // index counts this code point's continuation bytes only; every byte must be in 0x80..0xbf.
        for (unsigned index = 0; index < following; ++index) {
            const auto byte = static_cast<std::uint8_t>(value[position++]);
            if ((byte & 0xc0U) != 0x80U) {
                return false;
            }
            code = (code << 6) | (byte & 0x3fU);
        }
        if (code < minimum || code > 0x10ffffU || (code >= 0xd800U && code <= 0xdfffU)) {
            return false;
        }
    }
    return true;
}
} // namespace astra
