#pragma once

#include <string_view>

namespace obf {

enum class protection_level {
  none,
  light,
  strong,
  vm,
};

struct function_policy {
  protection_level level = protection_level::none;
  bool allow_string_encoding = false;
  bool allow_constant_encoding = false;
  bool allow_instruction_substitution = false;
  bool allow_bogus_control_flow = false;
  bool allow_opaque_predicates = false;
  bool allow_flattening = false;
  bool allow_split = false;
  bool allow_indirect_calls = false;
  bool allow_vm = false;
};

constexpr std::string_view to_string(protection_level level) {
  switch (level) {
  case protection_level::none:
    return "none";
  case protection_level::light:
    return "light";
  case protection_level::strong:
    return "strong";
  case protection_level::vm:
    return "vm";
  }

  return "none";
}

} // namespace obf
