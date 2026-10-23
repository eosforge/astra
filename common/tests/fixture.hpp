// Provide shared public test identities and fixture utilities without borrowing deployment credentials.
#pragma once
#include "identity.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace astra::test {
/// Public repository fixtures only; signing keys never come from environment or deployment directories.
std::string read(const std::filesystem::path& path);

/// Signs raw value with the public test key and default admission domain; returns an owned 64-byte signature.
std::string sign(std::string_view value, std::string_view domain = admissionSignatureDomain);
} // namespace astra::test
