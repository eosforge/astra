// Define domain scope keys and range selection shared by storage and protocol consumers.
#pragma once
#include <compare>
#include <cstddef>
#include <string>
#include <string_view>

namespace astra {
/// Business address matches two independent UTF-8 strings exactly, without slash-path or wildcard semantics.
struct Scope {
    /// First group, 1..128 bytes; __ prefix reserves internal data, rejected only at external entry points.
    std::string sector;
    /// Second group, 1..128 bytes, with storage independent of sector.
    std::string spectrum;
    /// Validates address text without role checks, allocation, or Unicode normalization.
    bool valid() const noexcept;
    /// Reports internal reservation; callers must first reject inputs that fail valid.
    bool internal() const noexcept;
    /// Validates nonempty complete UTF-8 without NUL, up to maximum bytes; zero accepts no text.
    static bool text(std::string_view value, std::size_t maximum) noexcept;
    /// Raw-byte lexical order supports stable routing and tests, not publication priority or permissions.
    auto operator<=>(const Scope&) const = default;
};
} // namespace astra
