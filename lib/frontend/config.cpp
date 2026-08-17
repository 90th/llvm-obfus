#include "obf/frontend/config.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"

#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <utility>

LLVM_YAML_IS_SEQUENCE_VECTOR(obf::function_override)
LLVM_YAML_IS_SEQUENCE_VECTOR(obf::target_rule)

namespace llvm::yaml {

template <>
struct ScalarEnumerationTraits<obf::protection_level> {
  static void enumeration(IO& io, obf::protection_level& level) {
    io.enumCase(level, "none", obf::protection_level::none);
    io.enumCase(level, "light", obf::protection_level::light);
    io.enumCase(level, "strong", obf::protection_level::strong);
    io.enumCase(level, "vm", obf::protection_level::vm);
    io.enumCase(level, "strong_vm", obf::protection_level::strong_vm);
  }
};

template <>
struct ScalarEnumerationTraits<obf::frontend_kind> {
  static void enumeration(IO& io, obf::frontend_kind& frontend) {
    io.enumCase(frontend, "generic", obf::frontend_kind::generic);
    io.enumCase(frontend, "rust", obf::frontend_kind::rust);
    io.enumCase(frontend, "zig", obf::frontend_kind::zig);
    io.enumCase(frontend, "tinygo", obf::frontend_kind::tinygo);
  }
};

template <>
struct ScalarEnumerationTraits<obf::config_profile> {
  static void enumeration(IO& io, obf::config_profile& profile) {
    io.enumCase(profile, "fast", obf::config_profile::fast);
    io.enumCase(profile, "standard", obf::config_profile::standard);
    io.enumCase(profile, "guarded", obf::config_profile::guarded);
    io.enumCase(profile, "fortress", obf::config_profile::fortress);
    io.enumCase(profile, "lab", obf::config_profile::lab);
  }
};

template <>
struct ScalarEnumerationTraits<obf::constant_protection_mode> {
  static void enumeration(IO& io, obf::constant_protection_mode& mode) {
    io.enumCase(mode, "off", obf::constant_protection_mode::off);
    io.enumCase(mode, "mba_inline", obf::constant_protection_mode::mba_inline);
    io.enumCase(mode, "keyed_pool", obf::constant_protection_mode::keyed_pool);
    io.enumCase(mode, "auto", obf::constant_protection_mode::auto_mode);
    io.enumCase(mode, "all", obf::constant_protection_mode::all);
  }
};

template <>
struct MappingTraits<obf::target_rule> {
  static void mapping(IO& io, obf::target_rule& rule) {
    io.mapRequired("match", rule.match);
    io.mapRequired("level", rule.level);
  }
};

template <>
struct MappingTraits<obf::function_override> {
  static void mapping(IO& io, obf::function_override& rule) {
    io.mapRequired("name", rule.name);
    io.mapRequired("level", rule.level);
  }
};

template <>
struct MappingTraits<obf::block_split_config> {
  static void mapping(IO& io, obf::block_split_config& config) {
    io.mapOptional("max_splits_per_function", config.max_splits_per_function, std::uint32_t{1});
    io.mapOptional(
        "min_instructions_per_block", config.min_instructions_per_block, std::uint32_t{2});
  }
};

template <>
struct MappingTraits<obf::string_encoding_config> {
  static void mapping(IO& io, obf::string_encoding_config& config) {
    io.mapOptional("min_string_length", config.min_string_length, std::uint32_t{2});
    io.mapOptional("max_strings_per_module", config.max_strings_per_module, std::uint32_t{64});
    io.mapOptional("prefer_lazy_decode", config.prefer_lazy_decode, true);
    io.mapOptional("allow_ctor_fallback", config.allow_ctor_fallback, true);
    io.mapOptional("authenticated_mode", config.authenticated_mode, false);
  }
};

template <>
struct MappingTraits<obf::constant_encoding_config> {
  static void mapping(IO& io, obf::constant_encoding_config& config) {
    io.mapOptional("mode", config.mode, obf::constant_protection_mode::mba_inline);
    io.mapOptional(
        "max_constants_per_function", config.max_constants_per_function, std::uint32_t{4});
    io.mapOptional("min_bit_width", config.min_bit_width, std::uint32_t{8});
  }
};

template <>
struct MappingTraits<obf::zero_comparison_config> {
  static void mapping(IO& io, obf::zero_comparison_config& config) {
    io.mapOptional("enabled", config.enabled, true);
    io.mapOptional("max_sites_per_function", config.max_sites_per_function, std::uint32_t{16});
    io.mapOptional("max_unroll_bytes", config.max_unroll_bytes, std::uint32_t{64});
    io.mapOptional("transform_string_comparisons", config.transform_string_comparisons, true);
    io.mapOptional("transform_integer_comparisons", config.transform_integer_comparisons, true);
  }
};

template <>
struct MappingTraits<obf::mba_config> {
  static void mapping(IO& io, obf::mba_config& config) {
    io.mapOptional("depth", config.depth, std::uint32_t{1});
    io.mapOptional("max_ir_instructions", config.max_ir_instructions);
    io.mapOptional("enable_polynomial", config.enable_polynomial);
    io.mapOptional("enable_multiplication", config.enable_multiplication);
  }
};

template <>
struct MappingTraits<obf::vm_config> {
  static void mapping(IO& io, obf::vm_config& config) {
    io.mapOptional("max_virtual_instructions", config.max_virtual_instructions, std::uint32_t{512});
    io.mapOptional("max_mba_depth", config.max_mba_depth);
  }
};

template <>
struct MappingTraits<obf::indirect_dispatch_config> {
  static void mapping(IO& io, obf::indirect_dispatch_config& config) {
    io.mapOptional("enabled", config.enabled, false);
    io.mapOptional("max_sites_per_function", config.max_sites_per_function, std::uint32_t{4});
    io.mapOptional("max_switch_targets", config.max_switch_targets, std::uint32_t{8});
    io.mapOptional("target_vm_dispatchers", config.target_vm_dispatchers, true);
    io.mapOptional("target_flattened_headers", config.target_flattened_headers, true);
  }
};

template <>
struct MappingTraits<obf::security_gate_config> {
  static void mapping(IO& io, obf::security_gate_config& config) {
    io.mapOptional("fail_on_public_obf_symbol", config.fail_on_public_obf_symbol, false);
    io.mapOptional("strip_release_markers", config.strip_release_markers, false);
    io.mapOptional("allow_unsafe_config", config.allow_unsafe_config, false);
  }
};

template <>
struct MappingTraits<obf::obfuscation_config> {
  static void mapping(IO& io, obf::obfuscation_config& config) {
    io.mapOptional("frontend", config.frontend, obf::frontend_kind::generic);

    io.mapOptional("profile", config.profile);
    io.mapOptional("seed", config.seed, std::uint64_t{0});
    io.mapOptional("default_level", config.default_level, obf::protection_level::none);
    io.mapOptional("overrides", config.overrides);
    io.mapOptional("targets", config.targets);
    io.mapOptional("block_split", config.block_split);
    io.mapOptional("string_encoding", config.string_encoding);
    io.mapOptional("constant_encoding", config.constant_encoding);
    io.mapOptional("zero_comparison", config.zero_comparison);
    io.mapOptional("mba", config.mba);
    io.mapOptional("vm", config.vm);
    io.mapOptional("indirect_dispatch", config.indirect_dispatch);
    io.mapOptional("security", config.security);
    io.mapOptional("debug_preserve_generated_names", config.debug_preserve_generated_names, false);
    io.mapOptional("emit_progress_warnings", config.emit_progress_warnings, false);
  }
};

}  // namespace llvm::yaml

namespace obf {

namespace {

struct config_parse_presence {
  bool has_document = false;
  bool multiple_documents = false;
  bool frontend = false;

  bool seed = false;
  bool default_level = false;
  bool overrides = false;
  bool targets = false;
  bool block_split = false;
  bool string_encoding = false;
  bool constant_encoding = false;
  bool mba = false;
  bool zero_comparison = false;
  bool vm = false;
  bool indirect_dispatch = false;
  bool security = false;
  bool debug_preserve_generated_names = false;
  bool emit_progress_warnings = false;
};

void mark_config_presence(config_parse_presence& presence, llvm::StringRef key) {
  if (key == "frontend") {
    presence.frontend = true;
  } else if (key == "seed") {
    presence.seed = true;
  } else if (key == "default_level") {
    presence.default_level = true;
  } else if (key == "overrides") {
    presence.overrides = true;
  } else if (key == "targets") {
    presence.targets = true;
  } else if (key == "block_split") {
    presence.block_split = true;
  } else if (key == "string_encoding") {
    presence.string_encoding = true;
  } else if (key == "constant_encoding") {
    presence.constant_encoding = true;
  } else if (key == "mba") {
    presence.mba = true;
  } else if (key == "zero_comparison") {
    presence.zero_comparison = true;
  } else if (key == "vm") {
    presence.vm = true;
  } else if (key == "indirect_dispatch") {
    presence.indirect_dispatch = true;
  } else if (key == "security") {
    presence.security = true;
  } else if (key == "debug_preserve_generated_names") {
    presence.debug_preserve_generated_names = true;
  } else if (key == "emit_progress_warnings") {
    presence.emit_progress_warnings = true;
  }
}

config_parse_presence collect_presence(llvm::StringRef text) {
  config_parse_presence presence;
  llvm::SourceMgr source_manager;
  llvm::yaml::Stream stream(text, source_manager);

  for (llvm::yaml::Document& document : stream) {
    llvm::yaml::Node* root = document.getRoot();
    if (root == nullptr || llvm::isa<llvm::yaml::NullNode>(root)) {
      if (root != nullptr) { root->skip(); }
      continue;
    }
    if (presence.has_document) {
      presence.multiple_documents = true;
      root->skip();
      continue;
    }
    presence.has_document = true;

    auto* mapping = llvm::dyn_cast<llvm::yaml::MappingNode>(root);
    if (mapping == nullptr) {
      root->skip();
      continue;
    }

    for (llvm::yaml::KeyValueNode& entry : *mapping) {
      llvm::SmallString<64> storage;
      if (auto* scalar = llvm::dyn_cast_or_null<llvm::yaml::ScalarNode>(entry.getKey())) {
        mark_config_presence(presence, scalar->getValue(storage));
      }
      if (llvm::yaml::Node* value = entry.getValue()) { value->skip(); }
    }
  }
  return presence;
}

obfuscation_config defaults_for_profile(config_profile profile) {
  obfuscation_config config;
  config.profile = profile;
  config.default_level = protection_level::none;
  config.constant_encoding.min_bit_width = 8;
  config.debug_preserve_generated_names = false;

  switch (profile) {
    case config_profile::fast:
      config.block_split = {.max_splits_per_function = 1, .min_instructions_per_block = 2};
      config.string_encoding = {.min_string_length = 3,
                                .max_strings_per_module = 32,
                                .prefer_lazy_decode = true,
                                .allow_ctor_fallback = true,
                                .authenticated_mode = false};
      config.constant_encoding.max_constants_per_function = 2;
      config.mba.depth = 1;
      config.security.fail_on_public_obf_symbol = false;
      break;
    case config_profile::standard:
      config.block_split = {.max_splits_per_function = 1, .min_instructions_per_block = 2};
      config.string_encoding = {.min_string_length = 2,
                                .max_strings_per_module = 128,
                                .prefer_lazy_decode = true,
                                .allow_ctor_fallback = true,
                                .authenticated_mode = false};
      config.constant_encoding.max_constants_per_function = 4;
      config.mba.depth = 1;
      config.security.fail_on_public_obf_symbol = true;
      break;
    case config_profile::guarded:
      config.block_split = {.max_splits_per_function = 2, .min_instructions_per_block = 2};
      config.string_encoding = {.min_string_length = 2,
                                .max_strings_per_module = 256,
                                .prefer_lazy_decode = true,
                                .allow_ctor_fallback = false,
                                .authenticated_mode = false};
      config.constant_encoding.max_constants_per_function = 8;
      config.mba.depth = 2;
      config.security.fail_on_public_obf_symbol = true;
      break;
    case config_profile::fortress:
      config.block_split = {.max_splits_per_function = 4, .min_instructions_per_block = 1};
      config.string_encoding = {.min_string_length = 1,
                                .max_strings_per_module = 512,
                                .prefer_lazy_decode = false,
                                .allow_ctor_fallback = false,
                                .authenticated_mode = false};
      config.constant_encoding.max_constants_per_function = 16;
      config.mba.depth = 3;
      config.security.fail_on_public_obf_symbol = true;
      break;
    case config_profile::lab:
      config.block_split = {.max_splits_per_function = 8, .min_instructions_per_block = 1};
      config.string_encoding = {.min_string_length = 1,
                                .max_strings_per_module = 1024,
                                .prefer_lazy_decode = false,
                                .allow_ctor_fallback = false,
                                .authenticated_mode = false};
      config.constant_encoding.max_constants_per_function = 32;
      config.mba.depth = 4;
      config.mba.max_ir_instructions = 320;
      config.mba.enable_polynomial = true;
      config.mba.enable_multiplication = true;
      config.security.fail_on_public_obf_symbol = true;
      break;
  }
  return config;
}

obfuscation_config apply_profile_defaults(const obfuscation_config& raw_config,
                                          const config_parse_presence& presence) {
  if (!raw_config.profile.has_value()) { return raw_config; }

  obfuscation_config config = defaults_for_profile(*raw_config.profile);
  if (presence.frontend) { config.frontend = raw_config.frontend; }
  if (presence.seed) { config.seed = raw_config.seed; }
  if (presence.default_level) { config.default_level = raw_config.default_level; }
  if (presence.overrides) { config.overrides = raw_config.overrides; }
  if (presence.targets) { config.targets = raw_config.targets; }
  if (presence.block_split) { config.block_split = raw_config.block_split; }
  if (presence.string_encoding) { config.string_encoding = raw_config.string_encoding; }
  if (presence.constant_encoding) { config.constant_encoding = raw_config.constant_encoding; }
  if (presence.zero_comparison) { config.zero_comparison = raw_config.zero_comparison; }
  if (presence.mba) { config.mba = raw_config.mba; }
  if (presence.vm) { config.vm = raw_config.vm; }
  if (presence.indirect_dispatch) { config.indirect_dispatch = raw_config.indirect_dispatch; }
  if (presence.security) { config.security = raw_config.security; }
  if (presence.debug_preserve_generated_names) {
    config.debug_preserve_generated_names = raw_config.debug_preserve_generated_names;
  }
  if (presence.emit_progress_warnings) {
    config.emit_progress_warnings = raw_config.emit_progress_warnings;
  }
  return config;
}

bool is_vm_level(protection_level level) {
  switch (level) {
    case protection_level::vm:
    case protection_level::strong_vm:
      return true;
    case protection_level::none:
    case protection_level::light:
    case protection_level::strong:
      return false;
  }
  llvm_unreachable("unknown protection level");
}

bool is_strong_vm_level(protection_level level) { return level == protection_level::strong_vm; }

bool config_selects_level(const obfuscation_config& config, bool (*predicate)(protection_level)) {
  if (predicate(config.default_level)) { return true; }
  for (const function_override& override : config.overrides) {
    if (predicate(override.level)) { return true; }
  }
  for (const target_rule& rule : config.targets) {
    if (predicate(rule.level)) { return true; }
  }
  return false;
}

bool config_selects_vm(const obfuscation_config& config) {
  return config_selects_level(config, is_vm_level);
}

bool config_selects_strong_vm(const obfuscation_config& config) {
  return config_selects_level(config, is_strong_vm_level);
}

bool is_high_security_profile(config_profile profile) {
  switch (profile) {
    case config_profile::fortress:
    case config_profile::lab:
      return true;
    case config_profile::fast:
    case config_profile::standard:
    case config_profile::guarded:
      return false;
  }
  llvm_unreachable("unknown config profile");
}

bool is_exact_function_name(llvm::StringRef name) {
  return !name.empty() && name.find_first_of("*?") == llvm::StringRef::npos;
}

bool is_light_or_strong(protection_level level) {
  return level == protection_level::light || level == protection_level::strong;
}

[[noreturn]] void report_non_generic_config_error(llvm::StringRef detail) {
  std::string message = "config error: non-generic frontend ";
  message.append(detail.data(), detail.size());
  llvm::report_fatal_error(llvm::StringRef(message));
}

[[noreturn]] void report_non_generic_named_config_error(llvm::StringRef entry,
                                                        llvm::StringRef name,
                                                        llvm::StringRef requirement) {
  std::string detail;
  detail.reserve(entry.size() + name.size() + requirement.size() + 4);
  detail.append(entry.data(), entry.size());
  detail += " '";
  detail.append(name.data(), name.size());
  detail += "'";
  if (!requirement.empty()) {
    detail += " ";
    detail.append(requirement.data(), requirement.size());
  }
  report_non_generic_config_error(detail);
}

[[noreturn]] void report_non_generic_alias_resolution_error(llvm::StringRef alias_name,
                                                            llvm::StringRef function_name) {
  std::string detail;
  detail.reserve(alias_name.size() + function_name.size() + 96);
  detail += "configured alias '";
  detail.append(alias_name.data(), alias_name.size());
  detail += "' resolves to function '";
  detail.append(function_name.data(), function_name.size());
  detail += "' whose name is not exact; aliases must resolve to names without '*' or '?'";
  report_non_generic_config_error(detail);
}

void validate_non_generic_config(const obfuscation_config& config) {
  if (config.security.allow_unsafe_config) {
    report_non_generic_config_error("forbids security.allow_unsafe_config");
  }
  if (config.default_level != protection_level::none) {
    report_non_generic_config_error("requires default_level: none");
  }
  if (!config.security.strip_release_markers) {
    report_non_generic_config_error("requires security.strip_release_markers: true");
  }
  if (config.frontend == frontend_kind::tinygo &&
      config.string_encoding.max_strings_per_module != 0) {
    report_non_generic_config_error(
        "requires string_encoding.max_strings_per_module: 0 for tinygo");
  }
  if (config.targets.empty() && config.overrides.empty()) {
    report_non_generic_config_error("requires at least one target or override");
  }

  llvm::StringSet<> target_names;
  for (const target_rule& rule : config.targets) {
    const llvm::StringRef name(rule.match);
    if (!is_exact_function_name(name)) {
      report_non_generic_named_config_error("target", name, "must use an exact function name");
    }
    if (!is_light_or_strong(rule.level)) {
      report_non_generic_config_error("entries must use light or strong");
    }
    if (!target_names.insert(name).second) {
      report_non_generic_named_config_error(
          "has duplicate configured function", name, "in targets");
    }
  }

  llvm::StringSet<> override_names;
  for (const function_override& override : config.overrides) {
    const llvm::StringRef name(override.name);
    if (!is_exact_function_name(name)) {
      report_non_generic_named_config_error("override", name, "must use an exact function name");
    }
    if (!is_light_or_strong(override.level)) {
      report_non_generic_config_error("entries must use light or strong");
    }
    if (!override_names.insert(name).second) {
      report_non_generic_named_config_error(
          "has duplicate configured function", name, "in overrides");
    }
    if (target_names.contains(name)) {
      report_non_generic_named_config_error("target/override overlap", name, "");
    }
  }
}

}  // namespace

const llvm::Function* resolve_configured_function(const llvm::Module& module,
                                                  llvm::StringRef name) {
  if (!is_exact_function_name(name)) { return nullptr; }

  const llvm::Function* function = module.getFunction(name);
  if (function == nullptr) {
    const llvm::GlobalAlias* alias = module.getNamedAlias(name);
    if (alias == nullptr) { return nullptr; }

    function = llvm::dyn_cast_or_null<llvm::Function>(alias->getAliaseeObject());
  }

  return function != nullptr && !function->isDeclaration() ? function : nullptr;
}

void validate_effective_config(const obfuscation_config& config) {
  if (config.frontend != frontend_kind::generic) { validate_non_generic_config(config); }

  if (config.vm.max_virtual_instructions == 0) {
    llvm::report_fatal_error("config error: vm.max_virtual_instructions must be >= 1");
  }
  if (config.security.allow_unsafe_config) { return; }

  if (config.debug_preserve_generated_names && config_selects_vm(config)) {
    llvm::report_fatal_error("security gate failure: debug names preserved with VM enabled");
  }

  if ((config_selects_strong_vm(config) ||
       (config.profile.has_value() && is_high_security_profile(*config.profile))) &&
      !config.security.fail_on_public_obf_symbol) {
    llvm::report_fatal_error(
        "security gate failure: strong_vm or high-security profile without "
        "fail_on_public_obf_symbol");
  }
}

void validate_effective_config(const obfuscation_config& config, const llvm::Module& module) {
  validate_effective_config(config);
  if (config.frontend == frontend_kind::generic) { return; }

  llvm::SmallPtrSet<const llvm::Function*, 8> configured_functions;
  const auto validate_configured_function = [&](llvm::StringRef name) {
    const llvm::Function* function = resolve_configured_function(module, name);
    if (function == nullptr) {
      report_non_generic_named_config_error(
          "configured function", name, "is not a defined function");
    }

    if (!is_exact_function_name(function->getName())) {
      report_non_generic_alias_resolution_error(name, function->getName());
    }
    if (!configured_functions.insert(function).second) {
      report_non_generic_named_config_error(
          "configured function",
          name,
          "resolves to a function already selected by another target or override");
    }
  };

  for (const target_rule& rule : config.targets) { validate_configured_function(rule.match); }
  for (const function_override& override : config.overrides) {
    validate_configured_function(override.name);
  }
}

llvm::StringRef to_string(frontend_kind frontend) {
  switch (frontend) {
    case frontend_kind::generic:
      return "generic";
    case frontend_kind::rust:
      return "rust";
    case frontend_kind::zig:
      return "zig";
    case frontend_kind::tinygo:
      return "tinygo";
  }
  llvm_unreachable("unknown frontend kind");
}

llvm::StringRef to_string(config_profile profile) {
  switch (profile) {
    case config_profile::fast:
      return "fast";
    case config_profile::standard:
      return "standard";
    case config_profile::guarded:
      return "guarded";
    case config_profile::fortress:
      return "fortress";
    case config_profile::lab:
      return "lab";
  }
  llvm_unreachable("unknown config profile");
}

llvm::StringRef to_string(constant_protection_mode mode) {
  switch (mode) {
    case constant_protection_mode::off:
      return "off";
    case constant_protection_mode::mba_inline:
      return "mba_inline";
    case constant_protection_mode::keyed_pool:
      return "keyed_pool";
    case constant_protection_mode::auto_mode:
      return "auto";
    case constant_protection_mode::all:
      return "all";
  }
  llvm_unreachable("unknown constant protection mode");
}

llvm::Expected<obfuscation_config> load_config_from_file(llvm::StringRef path) {
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffer_or_error =
      llvm::MemoryBuffer::getFile(path);
  if (!buffer_or_error) {
    return llvm::createStringError(
        buffer_or_error.getError(), "failed to read config '%s'", path.str().c_str());
  }

  const llvm::StringRef buffer = buffer_or_error.get()->getBuffer();
  const config_parse_presence presence = collect_presence(buffer);
  llvm::yaml::Input input(buffer);
  obfuscation_config config;
  if (presence.multiple_documents) {
    return llvm::createStringError(
        "failed to parse config '%s': multiple non-empty YAML documents are not supported",
        path.str().c_str());
  }
  input >> config;

  if (input.error()) {
    return llvm::createStringError(
        input.error(), "failed to parse config '%s'", path.str().c_str());
  }

  config = apply_profile_defaults(config, presence);
  return config;
}

std::string summarize_config(const obfuscation_config& config) {
  std::string output;
  llvm::raw_string_ostream stream(output);

  stream << "frontend: " << to_string(config.frontend) << '\n';
  stream << "profile: ";
  if (config.profile.has_value()) {
    stream << to_string(*config.profile);
  } else {
    stream << "legacy";
  }
  stream << '\n';
  stream << "seed: " << config.seed << '\n';
  stream << "default_level: " << to_string(config.default_level) << '\n';
  stream << "overrides: " << config.overrides.size() << '\n';
  for (const function_override& override : config.overrides) {
    stream << "  - name: " << override.name << ", level: " << to_string(override.level) << '\n';
  }
  stream << "targets: " << config.targets.size() << '\n';

  for (const target_rule& rule : config.targets) {
    stream << "  - match: " << rule.match << ", level: " << to_string(rule.level) << '\n';
  }

  stream << "block_split.max_splits_per_function: " << config.block_split.max_splits_per_function
         << '\n';
  stream << "block_split.min_instructions_per_block: "
         << config.block_split.min_instructions_per_block << '\n';
  stream << "string_encoding.min_string_length: " << config.string_encoding.min_string_length
         << '\n';
  stream << "string_encoding.max_strings_per_module: "
         << config.string_encoding.max_strings_per_module << '\n';
  stream << "string_encoding.prefer_lazy_decode: "
         << (config.string_encoding.prefer_lazy_decode ? "true" : "false") << '\n';
  stream << "string_encoding.allow_ctor_fallback: "
         << (config.string_encoding.allow_ctor_fallback ? "true" : "false") << '\n';
  stream << "string_encoding.authenticated_mode: "
         << (config.string_encoding.authenticated_mode ? "true" : "false") << '\n';
  stream << "constant_encoding.max_constants_per_function: "
         << config.constant_encoding.max_constants_per_function << '\n';
  stream << "constant_encoding.mode: " << to_string(config.constant_encoding.mode) << '\n';
  stream << "constant_encoding.min_bit_width: " << config.constant_encoding.min_bit_width << '\n';
  stream << "zero_comparison.enabled: " << (config.zero_comparison.enabled ? "true" : "false")
         << '\n';
  stream << "zero_comparison.max_sites_per_function: "
         << config.zero_comparison.max_sites_per_function << '\n';
  stream << "zero_comparison.max_unroll_bytes: " << config.zero_comparison.max_unroll_bytes << '\n';
  stream << "zero_comparison.transform_string_comparisons: "
         << (config.zero_comparison.transform_string_comparisons ? "true" : "false") << '\n';
  stream << "zero_comparison.transform_integer_comparisons: "
         << (config.zero_comparison.transform_integer_comparisons ? "true" : "false") << '\n';
  stream << "mba.depth: " << config.mba.depth << '\n';
  stream << "mba.max_ir_instructions: ";
  if (config.mba.max_ir_instructions.has_value()) {
    stream << *config.mba.max_ir_instructions;
  } else {
    stream << "derived";
  }
  stream << '\n';
  stream << "mba.enable_polynomial: ";
  if (config.mba.enable_polynomial.has_value()) {
    stream << (*config.mba.enable_polynomial ? "true" : "false");
  } else {
    stream << "derived";
  }
  stream << '\n';
  stream << "mba.enable_multiplication: ";
  if (config.mba.enable_multiplication.has_value()) {
    stream << (*config.mba.enable_multiplication ? "true" : "false");
  } else {
    stream << "derived";
  }
  stream << '\n';
  stream << "vm.max_virtual_instructions: " << config.vm.max_virtual_instructions << '\n';
  stream << "vm.max_mba_depth: ";
  if (config.vm.max_mba_depth.has_value()) {
    stream << *config.vm.max_mba_depth;
  } else {
    stream << "unclamped";
  }
  stream << '\n';
  stream << "indirect_dispatch.enabled: " << (config.indirect_dispatch.enabled ? "true" : "false")
         << '\n';
  stream << "indirect_dispatch.max_sites_per_function: "
         << config.indirect_dispatch.max_sites_per_function << '\n';
  stream << "indirect_dispatch.max_switch_targets: " << config.indirect_dispatch.max_switch_targets
         << '\n';
  stream << "indirect_dispatch.target_vm_dispatchers: "
         << (config.indirect_dispatch.target_vm_dispatchers ? "true" : "false") << '\n';
  stream << "indirect_dispatch.target_flattened_headers: "
         << (config.indirect_dispatch.target_flattened_headers ? "true" : "false") << '\n';
  stream << "security.strong_vm_invariants: always_enforced\n";
  stream << "security.fail_on_public_obf_symbol: "
         << (config.security.fail_on_public_obf_symbol ? "true" : "false") << '\n';
  stream << "security.strip_release_markers: "
         << (config.security.strip_release_markers ? "true" : "false") << '\n';
  stream << "security.allow_unsafe_config: "
         << (config.security.allow_unsafe_config ? "true" : "false") << '\n';
  stream << "debug_preserve_generated_names: "
         << (config.debug_preserve_generated_names ? "true" : "false") << '\n';
  stream << "emit_progress_warnings: " << (config.emit_progress_warnings ? "true" : "false")
         << '\n';

  return output;
}

}  // namespace obf
