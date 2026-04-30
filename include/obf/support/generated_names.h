#pragma once

#include "obf/support/stable_hash.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <string>

namespace obf {

inline std::uint64_t mix_generated_name_seed(std::uint64_t seed,
                                             std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

inline std::string make_obf_symbol_name(llvm::StringRef role,
                                        llvm::StringRef source_name,
                                        std::uint64_t seed) {
  std::uint64_t state = seed == 0 ? 0x6d2534f1f6c7a29bULL : seed;
  state = mix_generated_name_seed(
      state, stable_hash_string(role));
  state = mix_generated_name_seed(
      state, stable_hash_string(source_name));

  std::string material = llvm::utohexstr(state, /*LowerCase=*/true);
  while (material.size() < 12) {
    state = mix_generated_name_seed(state, material.size() + 1);
    material += llvm::utohexstr(state, /*LowerCase=*/true);
  }

  return (role + "_" + material.substr(0, 12)).str();
}

inline std::string make_unique_obf_symbol_name(llvm::Module &module,
                                               llvm::StringRef role,
                                               llvm::StringRef source_name,
                                               std::uint64_t seed) {
  const std::string base = make_obf_symbol_name(role, source_name, seed);
  if (module.getNamedValue(base) == nullptr) {
    return base;
  }

  for (std::uint64_t suffix = 1;; ++suffix) {
    const std::string candidate = base + "_" + std::to_string(suffix);
    if (module.getNamedValue(candidate) == nullptr) {
      return candidate;
    }
  }
}

} // namespace obf
