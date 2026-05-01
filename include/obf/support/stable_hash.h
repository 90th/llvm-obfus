#pragma once

#include "llvm/ADT/StringRef.h"

#include <cstdint>

namespace obf {

/// \brief Mix a seed with a salt using algebraic operations.
///
/// Produces deterministic output with high entropy dispersion for obfuscation
/// variant selection. Used extensively in VM instruction rewriting and handler
/// polymorphism to select between multiple implementation variants.
///
/// \param seed Base seed value (often derived from function name or bytecode)
/// \param salt Per-operation salt (instruction index, opcode, or local variation)
/// \return Mixed seed with high entropy dispersion
/// \note Deterministic: same (seed, salt) always produces same output
/// \note Not cryptographically secure; use for obfuscation only
inline std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

/// \brief Compute a stable 64-bit hash of a string.
///
/// Uses FNV-1a inspired algorithm with configurable seed for deterministic hashing.
/// Commonly used for generating unique obfuscation symbol names and deriving function
/// seeds from function names. Same input always produces same output across runs.
///
/// \param text String to hash
/// \param seed Optional starting seed for chaining/isolation (default 0)
/// \return 64-bit hash value
/// \note Deterministic: same (text, seed) always produces same output
/// \note Not cryptographically secure; use for obfuscation symbol generation only
inline std::uint64_t stable_hash_string(llvm::StringRef text, std::uint64_t seed = 0) {
  constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;

  std::uint64_t hash = kOffsetBasis ^ seed;
  for (const char byte : text) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= kPrime;
  }

  return hash;
}

}  // namespace obf
