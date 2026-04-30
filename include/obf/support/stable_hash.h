#pragma once

#include "llvm/ADT/StringRef.h"

#include <cstdint>

namespace obf {

inline std::uint64_t stable_hash_string(llvm::StringRef text,
                                        std::uint64_t seed = 0) {
  constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;

  std::uint64_t hash = kOffsetBasis ^ seed;
  for (const char byte : text) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= kPrime;
  }

  return hash;
}

} // namespace obf
