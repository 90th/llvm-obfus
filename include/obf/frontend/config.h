#pragma once

#include "obf/policy/function_policy.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"

#include <cstdint>
#include <string>
#include <vector>

namespace obf {

struct function_override {
  std::string name;
  protection_level level = protection_level::none;
};

struct target_rule {
  std::string match;
  protection_level level = protection_level::none;
};

struct block_split_config {
  std::uint32_t max_splits_per_function = 1;
  std::uint32_t min_instructions_per_block = 2;
};

struct string_encoding_config {
  std::uint32_t min_string_length = 2;
  std::uint32_t max_strings_per_module = 64;
  bool prefer_lazy_decode = true;
  bool allow_ctor_fallback = true;
  bool strong_vm_allow_global_plaintext = false;
  bool strong_vm_allow_lazy_decode = false;
  bool strong_vm_allow_ctor_fallback = false;
};

struct constant_encoding_config {
  std::uint32_t max_constants_per_function = 4;
  std::uint32_t min_bit_width = 8;
};

struct mba_config {
  std::uint32_t depth = 1;
};

struct obfuscation_config {
  std::uint64_t seed = 0;
  protection_level default_level = protection_level::none;
  std::vector<function_override> overrides;
  std::vector<target_rule> targets;
  block_split_config block_split;
  string_encoding_config string_encoding;
  constant_encoding_config constant_encoding;
  mba_config mba;
};

llvm::Expected<obfuscation_config> load_config_from_file(llvm::StringRef path);
std::string summarize_config(const obfuscation_config &config);

} // namespace obf
