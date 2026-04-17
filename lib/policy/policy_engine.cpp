#include "obf/policy/policy_engine.h"

#include "llvm/IR/Module.h"

namespace obf {

namespace {

bool wildcard_match(llvm::StringRef pattern, llvm::StringRef text) {
  std::size_t pattern_index = 0;
  std::size_t text_index = 0;
  std::size_t star_index = llvm::StringRef::npos;
  std::size_t match_index = 0;

  while (text_index < text.size()) {
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == '?' ||
         pattern[pattern_index] == text[text_index])) {
      ++pattern_index;
      ++text_index;
      continue;
    }

    if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      star_index = pattern_index++;
      match_index = text_index;
      continue;
    }

    if (star_index != llvm::StringRef::npos) {
      pattern_index = star_index + 1;
      text_index = ++match_index;
      continue;
    }

    return false;
  }

  while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
    ++pattern_index;
  }

  return pattern_index == pattern.size();
}

std::uint64_t hash_string(llvm::StringRef text, std::uint64_t seed) {
  constexpr std::uint64_t kOffsetBasis = 1469598103934665603ULL;
  constexpr std::uint64_t kPrime = 1099511628211ULL;

  std::uint64_t hash = kOffsetBasis ^ seed;
  for (const char byte : text) {
    hash ^= static_cast<unsigned char>(byte);
    hash *= kPrime;
  }

  return hash;
}

std::uint64_t derive_seed(const llvm::Module &module,
                          llvm::StringRef function_name,
                          std::uint64_t top_level_seed) {
  std::uint64_t hash = hash_string(module.getName(), top_level_seed);
  return hash_string(function_name, hash);
}

const target_rule *find_matching_rule(const obfuscation_config &config,
                                      llvm::StringRef function_name) {
  for (const target_rule &rule : config.targets) {
    if (wildcard_match(rule.match, function_name)) {
      return &rule;
    }
  }

  return nullptr;
}

const function_override *find_explicit_override(const obfuscation_config &config,
                                                llvm::StringRef function_name) {
  for (const function_override &override : config.overrides) {
    if (override.name == function_name) {
      return &override;
    }
  }

  return nullptr;
}

std::optional<protection_level>
classify_from_features(const function_features &features, std::string &detail) {
  if (features.string_ref_count > 0) {
    detail = "automatic:string-sensitive";
    return protection_level::light;
  }

  if (features.cyclomatic_complexity >= 3 && features.instruction_count <= 128 &&
      !features.address_taken) {
    detail = "automatic:control-sensitive";
    return protection_level::strong;
  }

  return std::nullopt;
}

std::optional<protection_level>
derive_minimum_security_floor(const function_features &features) {
  const llvm::StringRef function_name(features.name);
  if (function_name.starts_with("__obf_") || function_name.starts_with("llvm.")) {
    return std::nullopt;
  }

  if (features.cyclomatic_complexity >= 3 && features.instruction_count <= 128 &&
      !features.address_taken) {
    return protection_level::strong;
  }

  if (features.string_ref_count > 0) {
    return protection_level::light;
  }

  return std::nullopt;
}

bool satisfies_security_floor(protection_level selected,
                             protection_level minimum_floor) {
  switch (minimum_floor) {
  case protection_level::none:
    return true;
  case protection_level::light:
    return selected != protection_level::none;
  case protection_level::strong:
    return selected == protection_level::strong || selected == protection_level::vm ||
           selected == protection_level::strong_vm;
  case protection_level::vm:
    return selected == protection_level::vm || selected == protection_level::strong_vm;
  case protection_level::strong_vm:
    return selected == protection_level::strong_vm;
  }

  return false;
}

function_policy promote_to_security_floor(function_policy current,
                                          protection_level minimum_floor) {
  if (satisfies_security_floor(current.level, minimum_floor)) {
    return current;
  }

  switch (minimum_floor) {
  case protection_level::light:
    return make_function_policy(protection_level::light);
  case protection_level::strong:
    return make_function_policy(protection_level::strong);
  case protection_level::vm:
    return make_function_policy(protection_level::vm);
  case protection_level::strong_vm:
    return make_function_policy(protection_level::strong_vm);
  case protection_level::none:
    return current;
  }

  return current;
}

void append_detail(std::string &detail, llvm::StringRef suffix) {
  if (!detail.empty()) {
    detail += "; ";
  }

  detail += suffix.str();
}

} // namespace

std::optional<protection_level> parse_protection_level(llvm::StringRef text) {
  llvm::StringRef normalized = text.trim();
  if (normalized.starts_with("obf:")) {
    normalized = normalized.drop_front(4);
  }

  if (normalized.equals_insensitive("none")) {
    return protection_level::none;
  }

  if (normalized.equals_insensitive("light")) {
    return protection_level::light;
  }

  if (normalized.equals_insensitive("strong")) {
    return protection_level::strong;
  }

  if (normalized.equals_insensitive("vm")) {
    return protection_level::vm;
  }

  if (normalized.equals_insensitive("strong_vm")) {
    return protection_level::strong_vm;
  }

  return std::nullopt;
}

function_policy make_function_policy(protection_level level) {
  switch (level) {
  case protection_level::none:
    return {};
  case protection_level::light:
    return {.level = level,
            .allow_string_encoding = true,
            .allow_constant_encoding = true,
            .allow_instruction_substitution = false,
            .allow_opaque_gep = false,
            .allow_function_outlining = false,
            .allow_bogus_control_flow = false,
            .allow_opaque_predicates = false,
            .allow_flattening = false,
            .allow_split = true,
            .allow_indirect_calls = false,
            .allow_vm = false};
  case protection_level::strong:
    return {.level = level,
            .allow_string_encoding = true,
            .allow_constant_encoding = true,
            .allow_instruction_substitution = true,
            .allow_opaque_gep = true,
            .allow_function_outlining = true,
            .allow_bogus_control_flow = true,
            .allow_opaque_predicates = true,
            .allow_flattening = true,
            .allow_split = true,
            .allow_indirect_calls = true,
            .allow_vm = false};
  case protection_level::vm:
    return {.level = level,
            .allow_string_encoding = true,
            .allow_constant_encoding = true,
            .allow_instruction_substitution = false,
            .allow_opaque_gep = false,
            .allow_function_outlining = false,
            .allow_bogus_control_flow = false,
            .allow_opaque_predicates = false,
            .allow_flattening = false,
            .allow_split = true,
            .allow_indirect_calls = true,
            .allow_vm = true};
  case protection_level::strong_vm:
    return {.level = level,
            .allow_string_encoding = true,
            .allow_constant_encoding = false,
            .allow_instruction_substitution = true,
            .allow_opaque_gep = true,
            .allow_function_outlining = true,
            .allow_bogus_control_flow = false,
            .allow_opaque_predicates = false,
            .allow_flattening = true,
            .allow_split = false,
            .allow_indirect_calls = true,
            .allow_vm = true};
  }

  return {};
}

policy_decision select_policy(const llvm::Module &module,
                              const function_features &features,
                              const obfuscation_config &config,
                              llvm::StringRef annotation_text) {
  policy_decision decision;
  decision.seed = derive_seed(module, features.name, config.seed);
  decision.minimum_security_floor = derive_minimum_security_floor(features);

  if (const function_override *override =
          find_explicit_override(config, features.name)) {
    decision.source = policy_source::explicit_override;
    decision.detail = "override:" + override->name;
    decision.policy = make_function_policy(override->level);
  } else if (const auto annotation_level = parse_protection_level(annotation_text)) {
    decision.source = policy_source::source_annotation;
    decision.detail = ("annotation:" + annotation_text.trim()).str();
    decision.policy = make_function_policy(*annotation_level);
  } else if (const target_rule *rule =
                 find_matching_rule(config, features.name)) {
    decision.source = policy_source::config_rule;
    decision.detail = "config match:" + rule->match;
    decision.policy = make_function_policy(rule->level);
  } else {
    std::string automatic_detail;
    if (const auto automatic_level =
            classify_from_features(features, automatic_detail)) {
      decision.source = policy_source::automatic_analysis;
      decision.detail = automatic_detail;
      decision.policy = make_function_policy(*automatic_level);
    } else {
      decision.source = policy_source::default_policy;
      decision.detail = "default";
      decision.policy = make_function_policy(config.default_level);
    }
  }

  if (decision.minimum_security_floor.has_value() &&
      !satisfies_security_floor(decision.policy.level,
                                *decision.minimum_security_floor)) {
    decision.policy = promote_to_security_floor(
        decision.policy, *decision.minimum_security_floor);
    const std::string floor_detail =
        "minimum security floor raised to " +
        std::string(to_string(*decision.minimum_security_floor));
    append_detail(decision.detail, floor_detail);
  }

  if (features.is_declaration) {
    decision.policy = make_function_policy(protection_level::none);
    append_detail(decision.detail, "declaration forced none");
    return decision;
  }

  if (features.has_exception_edges || features.has_inline_asm) {
    if (decision.source == policy_source::explicit_override) {
      append_detail(decision.detail,
                    "explicit override kept despite risky features");
      decision.policy.allow_vm = false;
    } else {
      if (decision.policy.level == protection_level::vm) {
        decision.policy = make_function_policy(protection_level::light);
        append_detail(decision.detail, "risky features downgraded vm to light");
      } else if (decision.policy.level == protection_level::strong) {
        decision.policy = make_function_policy(protection_level::light);
        append_detail(decision.detail,
                      "risky features downgraded strong to light");
      } else if (decision.policy.level == protection_level::strong_vm) {
        decision.policy = make_function_policy(protection_level::light);
        append_detail(decision.detail,
                      "risky features downgraded strong_vm to light");
      }

      decision.policy.allow_flattening = false;
      decision.policy.allow_instruction_substitution = false;
      decision.policy.allow_function_outlining = false;
      decision.policy.allow_bogus_control_flow = false;
      decision.policy.allow_opaque_predicates = false;
      decision.policy.allow_split = false;
      decision.policy.allow_indirect_calls = false;
      decision.policy.allow_vm = false;
    }
  }

  if (features.address_taken) {
    if (decision.policy.level == protection_level::vm) {
      decision.policy = make_function_policy(protection_level::strong);
      append_detail(decision.detail, "address-taken forced vm to strong");
    } else if (decision.policy.level == protection_level::strong_vm) {
      decision.policy = make_function_policy(protection_level::strong);
      append_detail(decision.detail, "address-taken forced strong_vm to strong");
    }

    decision.policy.allow_vm = false;
  }

  if (decision.policy.level != protection_level::none) {
    decision.policy.allow_string_encoding = true;
    if (decision.policy.level != protection_level::strong_vm) {
      decision.policy.allow_constant_encoding = true;
    }
  }

  return decision;
}

} // namespace obf
