#pragma once

#include "obf/policy/function_policy.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/STLFunctionalExtras.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace llvm {
class Module;
}

namespace obf {

enum class string_encoding_mode {
  skipped,
  global_ctor,
  lazy_decode,
  inline_stack_decode,
};

enum class string_strategy_kind {
  none,
  helper_global_ctor,
  helper_lazy_decode,
  inline_stack_decode,
};

enum class string_helper_shape {
  none,
  ctor_unrolled_v0,
  lazy_flag_unrolled_v0,
  lazy_flag_reverse_v1,
  lazy_counter_chunked_v2,
  lazy_cached_pointer_v3,
};

enum class string_key_schedule_kind {
  seeded_byte_xor_v0,
  mixed_runtime_byte_xor_v1,
  cfg_path_byte_xor_v2,
};

struct string_encoding_options {
  std::size_t min_string_length = 2;
  std::size_t max_strings_per_module = 64;
  unsigned ctor_priority = 0;
  bool prefer_lazy_decode = true;
  bool allow_ctor_fallback = true;
};

struct string_encoding_result {
  std::string global_name;
  string_encoding_mode mode = string_encoding_mode::skipped;
  string_strategy_kind strategy_kind = string_strategy_kind::none;
  string_helper_shape helper_shape = string_helper_shape::none;
  string_key_schedule_kind key_schedule =
      string_key_schedule_kind::seeded_byte_xor_v0;
  std::string detail;
  std::string inline_detail;
  std::string fallback_reason;
  int merge_group = -1;
  int descriptor_index = -1;
  std::size_t rewritten_use_count = 0;
  std::size_t protected_use_count = 0;
  std::size_t unprotected_use_count = 0;
  bool inline_eligible = false;
  bool applied = false;
  std::vector<std::string> use_kinds;
};

using protected_function_seed_lookup =
    llvm::function_ref<std::optional<std::uint64_t>(llvm::StringRef)>;
using protected_function_level_lookup =
    llvm::function_ref<std::optional<protection_level>(llvm::StringRef)>;

std::string to_string(string_encoding_mode mode);
std::string to_string(string_strategy_kind kind);
std::string to_string(string_helper_shape shape);
std::string to_string(string_key_schedule_kind schedule);

std::vector<string_encoding_result>
analyze_string_encoding(const llvm::Module &module,
                        protected_function_seed_lookup get_seed,
                        protected_function_level_lookup get_level,
                        const string_encoding_options &options,
                        std::uint64_t module_seed);

std::vector<string_encoding_result>
run_string_encoding(llvm::Module &module,
                    protected_function_seed_lookup get_seed,
                    protected_function_level_lookup get_level,
                    const string_encoding_options &options,
                    std::uint64_t module_seed);

} // namespace obf
