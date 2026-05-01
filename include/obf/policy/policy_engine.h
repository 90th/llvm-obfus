#pragma once

#include "obf/analysis/function_features.h"
#include "obf/frontend/config.h"
#include "obf/policy/function_policy.h"

#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace llvm {
class Module;
}

namespace obf {

enum class policy_source {
  default_policy,
  automatic_analysis,
  config_rule,
  source_annotation,
  explicit_override,
};

struct policy_decision {
  function_policy policy;
  policy_source source = policy_source::default_policy;
  std::string detail;
  std::uint64_t seed = 0;
  std::optional<protection_level> minimum_security_floor;
};

constexpr std::string_view to_string(policy_source source) {
  switch (source) {
    case policy_source::default_policy:
      return "default";
    case policy_source::automatic_analysis:
      return "automatic_analysis";
    case policy_source::config_rule:
      return "config_rule";
    case policy_source::source_annotation:
      return "source_annotation";
    case policy_source::explicit_override:
      return "explicit_override";
  }

  return "default";
}

std::optional<protection_level> parse_protection_level(llvm::StringRef text);
function_policy make_function_policy(protection_level level);

policy_decision select_policy(const llvm::Module& module,
                              const function_features& features,
                              const obfuscation_config& config,
                              llvm::StringRef annotation_text);

}  // namespace obf
