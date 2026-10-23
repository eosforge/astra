// Provide shared Pulsar authority fixtures and lifecycle ownership for tests.
#pragma once
#include "check.hpp"
#include "fixture.hpp"

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>

namespace astra::test {
/// Owns one mkdtemp-created directory and cleans only its resources.
class Directory {
public:
    /// Owned temporary directory beneath the current test working directory.
    std::filesystem::path path;

    /// Create a unique directory with mkdtemp; throw if creation fails before ownership is acquired.
    Directory();

    /// Cleanup uses error_code so destruction cannot replace a propagating test exception.
    ~Directory();

    /// A temporary directory has exactly one cleanup owner.
    Directory(const Directory&) = delete;

    /// Do not replace cleanup responsibility through copy assignment.
    Directory& operator=(const Directory&) = delete;
};

/// Creates an owned test member; index is 1..255 for endpoint/principal fixtures, with Star as the default role.
Member member(unsigned index, Member::Role role = Member::Role::Star);
} // namespace astra::test
