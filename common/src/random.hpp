// Fill identity material from the operating system's cryptographic random source.
#pragma once
#include <cstdint>
#include <span>

namespace astra {
/// Fill every byte or throw before the caller can publish identity material.
void random(std::span<std::uint8_t> bytes);
} // namespace astra
