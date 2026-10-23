// Provide independent RFC 3629 scalar encoding and literal UTF-8 expectations for native consumers.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <utility>

namespace astra::test {
/// Own literal bytes and their syntax result independently of every production decoder.
struct Text {
    /// Preserve embedded NUL and non-ASCII bytes without C-string truncation.
    std::string bytes;
    /// Require nonempty, complete shortest-form UTF-8 with no NUL, as the protocol specifies.
    bool accepted;
};

/// Anchor the reference encoder at each width, surrogate neighbor and highest scalar.
inline const std::array scalars{
    std::pair{std::uint32_t{0x7f}, std::string("\x7f")},
    std::pair{std::uint32_t{0x80}, std::string("\xc2\x80")},
    std::pair{std::uint32_t{0x7ff}, std::string("\xdf\xbf")},
    std::pair{std::uint32_t{0x800}, std::string("\xe0\xa0\x80")},
    std::pair{std::uint32_t{0xd7ff}, std::string("\xed\x9f\xbf")},
    std::pair{std::uint32_t{0xe000}, std::string("\xee\x80\x80")},
    std::pair{std::uint32_t{0xffff}, std::string("\xef\xbf\xbf")},
    std::pair{std::uint32_t{0x10000}, std::string("\xf0\x90\x80\x80")},
    std::pair{std::uint32_t{0x10ffff}, std::string("\xf4\x8f\xbf\xbf")},
};

/// Cover literal malformed sequences and legal raw-byte identifiers from RFC 3629 sections 3-4.
inline const std::array texts{
    Text{"", false},
    Text{std::string(1, '\0'), false},
    Text{std::string("a\0b", 3), false},
    Text{"\x80", false},
    Text{"\xbf", false},
    Text{"\xc0\x80", false},
    Text{"\xc1\xbf", false},
    Text{"\xc2", false},
    Text{"\xc2\x7f", false},
    Text{"\xc2\xc0", false},
    Text{"\xdf\xc0", false},
    Text{"\xe0\x80\x80", false},
    Text{"\xe0\x9f\xbf", false},
    Text{"\xe0\xa0", false},
    Text{"\xe1\x80\x7f", false},
    Text{"\xed\xa0\x80", false},
    Text{"\xed\xbf\xbf", false},
    Text{"\xf0\x80\x80\x80", false},
    Text{"\xf0\x8f\xbf\xbf", false},
    Text{"\xf0\x90\x80", false},
    Text{"\xf1\x80\x7f\x80", false},
    Text{"\xf1\x80\x80\xc0", false},
    Text{"\xf4\x90\x80\x80", false},
    Text{"\xf5\x80\x80\x80", false},
    Text{"\xf8\x88\x80\x80\x80", false},
    Text{"\xfc\x84\x80\x80\x80\x80", false},
    Text{"\xfe", false},
    Text{"\xff", false},
    Text{std::string("\xf0\x90\x80\0", 4), false},
    Text{"*", true},
    Text{"a/b", true},
    Text{"../x", true},
    Text{" ", true},
    Text{"__", true},
    Text{"\xef\xbb\xbf", true},
    Text{"\xc3\xa9", true},
    Text{"e\xcc\x81", true},
    Text{"\xf4\x8f\xbf\xbf", true},
};

/// Encode one Unicode scalar from RFC 3629 section 3, independently of the production decoder.
std::string encoded(std::uint32_t value);
} // namespace astra::test
