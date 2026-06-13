#pragma once

#include "obf/support/stable_hash.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"

#include <string>

namespace obf::support {

inline std::string sanitize_ir_name(llvm::StringRef name) {
  std::string result;
  result.reserve(name.size());
  for (const char ch : name) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
      result.push_back(ch);
    } else {
      result.push_back('_');
    }
  }

  return result;
}

inline std::string scoped_ir_name(llvm::StringRef prefix,
                                  llvm::StringRef role,
                                  unsigned ordinal) {
  return (prefix.str() + "." + role.str() + std::to_string(ordinal));
}

inline std::string scoped_ir_name(llvm::StringRef prefix,
                                  llvm::StringRef role) {
  return (prefix.str() + "." + role.str());
}

inline std::string shard_name(std::uint64_t seed, std::uint64_t index) {
  return "__obf_shard_" +
         llvm::utohexstr(mix_seed(seed == 0 ? 0xbadc0ffee0ddf00dULL : seed, index + 1),
                         /*LowerCase=*/true);
}

inline std::string obfuscated_symbol_name(llvm::StringRef module_name,
                                          llvm::StringRef original_name,
                                          std::uint64_t seed_base,
                                          std::uint64_t ordinal) {
  std::uint64_t state = seed_base == 0 ? 0x6d2534f1f6c7a29bULL : seed_base;
  state = mix_seed(state, stable_hash_string(module_name));
  state = mix_seed(state, stable_hash_string(original_name));
  state = mix_seed(state, ordinal + 1);

  const std::size_t hex_length = 12 + static_cast<std::size_t>(state & 0xfU);
  std::string material;
  material.reserve(hex_length + 16);
  while (material.size() < hex_length) {
    material += llvm::utohexstr(state, /*LowerCase=*/true);
    state = mix_seed(state, material.size() + 1);
  }

  return "_" + material.substr(0, hex_length);
}

}  // namespace obf::support
