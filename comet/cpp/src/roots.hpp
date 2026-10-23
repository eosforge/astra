// Expose build-selected CA bytes to private SDK transport setup without exporting trust internals.
#pragma once
#include <string_view>

namespace comet::detail {
/// Embeds public CA PEM only; CMake rejects PRIVATE KEY markers. External files take priority; system trust is untouched.
inline std::string_view roots() noexcept {
#ifdef COMET_CA_GENERATED
    // CMake-generated public PEM bytes in SDK static storage; length excludes the extra NUL.
    static constexpr char certificate[] = {
#include "comet_ca.inc"
    };
    return {certificate, sizeof(certificate)};
#else
    return {};
#endif
}
} // namespace comet::detail
