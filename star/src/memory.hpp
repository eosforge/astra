// Configure only the owning Star process before any project runtime threads start.
#pragma once

namespace astra::memory {
/// Apply the native allocator default before runtime creation, preserving explicit operator overrides; false rejects startup.
[[nodiscard]] bool prepare() noexcept;
} // namespace astra::memory
