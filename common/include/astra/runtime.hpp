// Shared process entry owns startup, runtime loop, and signal handling.
#pragma once
#include <astra/policy.hpp>

namespace astra {
/// Shared Star/Planet entry. Borrows main's argc/argv; role must match the non-null concrete Policy factory.
/// Owns signals and network-resource lifetime, uses no stdin shutdown interaction, and keeps authentication material inside exception boundaries.
/// Returns 0 for graceful exit, 1 for fatal runtime failure, and 2 for invalid command-line input.
int runNode(int argc, char** argv, Member::Role role, PolicyFactory factory);
} // namespace astra
