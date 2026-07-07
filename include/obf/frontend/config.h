#pragma once

#include "obf/policy/function_policy.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"

#include <cstdint>
#include <optional>
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

enum class config_profile {
  fast,
  standard,
  guarded,
  fortress,
  lab,
};

enum class constant_protection_mode {
  off,
  mba_inline,
  keyed_pool,
  auto_mode,
  all,
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
  bool authenticated_mode = false;
};

struct constant_encoding_config {
  constant_protection_mode mode = constant_protection_mode::mba_inline;
  std::uint32_t max_constants_per_function = 4;
  std::uint32_t min_bit_width = 8;
};

struct mba_config {
  std::uint32_t depth = 1;
  std::optional<std::uint32_t> max_ir_instructions;
  std::optional<bool> enable_polynomial;
  std::optional<bool> enable_multiplication;
};

struct indirect_dispatch_config {
  bool enabled = false;
  std::uint32_t max_sites_per_function = 4;
  std::uint32_t max_switch_targets = 8;
  bool target_vm_dispatchers = true;
  bool target_flattened_headers = true;
};

struct security_gate_config {
  bool fail_on_public_obf_symbol = false;
  bool strip_release_markers = false;
  bool allow_unsafe_config = false;
};

struct obfuscation_config {
  std::optional<config_profile> profile;
  std::uint64_t seed = 0;
  protection_level default_level = protection_level::none;
  std::vector<function_override> overrides;
  std::vector<target_rule> targets;
  block_split_config block_split;
  string_encoding_config string_encoding;
  constant_encoding_config constant_encoding;
  mba_config mba;
  indirect_dispatch_config indirect_dispatch;
  security_gate_config security;
  bool debug_preserve_generated_names = false;
};

llvm::Expected<obfuscation_config> load_config_from_file(llvm::StringRef path);
std::string summarize_config(const obfuscation_config& config);
llvm::StringRef to_string(config_profile profile);
llvm::StringRef to_string(constant_protection_mode mode);

}  // namespace obf
