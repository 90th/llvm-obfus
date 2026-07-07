#include "obf/frontend/config.h"

#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string_view>
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
struct MappingTraits<obf::mba_config> {
  static void mapping(IO& io, obf::mba_config& config) {
    io.mapOptional("depth", config.depth, std::uint32_t{1});
    io.mapOptional("max_ir_instructions", config.max_ir_instructions);
    io.mapOptional("enable_polynomial", config.enable_polynomial);
    io.mapOptional("enable_multiplication", config.enable_multiplication);
  }
};

template <>
struct MappingTraits<obf::indirect_dispatch_config> {
  static void mapping(IO& io, obf::indirect_dispatch_config& config) {
    io.mapOptional("enabled", config.enabled, false);
    io.mapOptional(
        "max_sites_per_function", config.max_sites_per_function, std::uint32_t{4});
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
    io.mapOptional("profile", config.profile);
    io.mapOptional("seed", config.seed, std::uint64_t{0});
    io.mapOptional("default_level", config.default_level, obf::protection_level::none);
    io.mapOptional("overrides", config.overrides);
    io.mapOptional("targets", config.targets);
    io.mapOptional("block_split", config.block_split);
    io.mapOptional("string_encoding", config.string_encoding);
    io.mapOptional("constant_encoding", config.constant_encoding);
    io.mapOptional("mba", config.mba);
    io.mapOptional("indirect_dispatch", config.indirect_dispatch);
    io.mapOptional("security", config.security);
    io.mapOptional("debug_preserve_generated_names", config.debug_preserve_generated_names, false);
  }
};

}  // namespace llvm::yaml

namespace obf {

namespace {

struct config_parse_presence {
  bool seed = false;
  bool default_level = false;
  bool overrides = false;
  bool targets = false;
  bool block_split = false;
  bool string_encoding = false;
  bool constant_encoding = false;
  bool mba = false;
  bool indirect_dispatch = false;
  bool security = false;
  bool debug_preserve_generated_names = false;
};

bool has_top_level_key(llvm::StringRef text, llvm::StringRef key) {
  std::size_t offset = 0;
  while (offset < text.size()) {
    const std::size_t line_end = text.find('\n', offset);
    llvm::StringRef line =
        line_end == llvm::StringRef::npos ? text.substr(offset) : text.slice(offset, line_end);
    offset = line_end == llvm::StringRef::npos ? text.size() : line_end + 1;

    if (line.empty() || line.front() == ' ' || line.front() == '\t') { continue; }
    const std::size_t comment = line.find('#');
    if (comment != llvm::StringRef::npos) { line = line.take_front(comment); }
    line = line.rtrim();
    if (line.consume_front(key) && line.ltrim().starts_with(":")) { return true; }
  }
  return false;
}

config_parse_presence collect_presence(llvm::StringRef text) {
  return {.seed = has_top_level_key(text, "seed"),
          .default_level = has_top_level_key(text, "default_level"),
          .overrides = has_top_level_key(text, "overrides"),
          .targets = has_top_level_key(text, "targets"),
          .block_split = has_top_level_key(text, "block_split"),
          .string_encoding = has_top_level_key(text, "string_encoding"),
          .constant_encoding = has_top_level_key(text, "constant_encoding"),
          .mba = has_top_level_key(text, "mba"),
          .indirect_dispatch = has_top_level_key(text, "indirect_dispatch"),
          .security = has_top_level_key(text, "security"),
          .debug_preserve_generated_names =
              has_top_level_key(text, "debug_preserve_generated_names")};
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
  if (presence.seed) { config.seed = raw_config.seed; }
  if (presence.default_level) { config.default_level = raw_config.default_level; }
  if (presence.overrides) { config.overrides = raw_config.overrides; }
  if (presence.targets) { config.targets = raw_config.targets; }
  if (presence.block_split) { config.block_split = raw_config.block_split; }
  if (presence.string_encoding) { config.string_encoding = raw_config.string_encoding; }
  if (presence.constant_encoding) { config.constant_encoding = raw_config.constant_encoding; }
  if (presence.mba) { config.mba = raw_config.mba; }
  if (presence.indirect_dispatch) { config.indirect_dispatch = raw_config.indirect_dispatch; }
  if (presence.security) { config.security = raw_config.security; }
  if (presence.debug_preserve_generated_names) {
    config.debug_preserve_generated_names = raw_config.debug_preserve_generated_names;
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

bool is_strong_vm_level(protection_level level) {
  return level == protection_level::strong_vm;
}

bool config_selects_level(const obfuscation_config& config,
                          bool (*predicate)(protection_level)) {
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

llvm::Error validate_security_preflight(const obfuscation_config& config) {
  if (config.security.allow_unsafe_config) { return llvm::Error::success(); }

  if (config.debug_preserve_generated_names && config_selects_vm(config)) {
    return llvm::createStringError(
        llvm::inconvertibleErrorCode(),
        "security preflight failure: vm/strong_vm config cannot use "
        "debug_preserve_generated_names: true; disable debug_preserve_generated_names or set "
        "security.allow_unsafe_config: true");
  }

  if (config_selects_strong_vm(config) && !config.security.fail_on_public_obf_symbol) {
    return llvm::createStringError(
        llvm::inconvertibleErrorCode(),
        "security preflight failure: strong_vm config requires "
        "security.fail_on_public_obf_symbol: true; enable the public-symbol gate or set "
        "security.allow_unsafe_config: true");
  }

  if (config.profile.has_value() && is_high_security_profile(*config.profile) &&
      !config.security.fail_on_public_obf_symbol) {
    return llvm::createStringError(
        llvm::inconvertibleErrorCode(),
        "security preflight failure: profile %s requires "
        "security.fail_on_public_obf_symbol: true; enable the public-symbol gate or set "
        "security.allow_unsafe_config: true",
        to_string(*config.profile).str().c_str());
  }

  return llvm::Error::success();
}

}  // namespace

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
  input >> config;

  if (input.error()) {
    return llvm::createStringError(
        input.error(), "failed to parse config '%s'", path.str().c_str());
  }

  config = apply_profile_defaults(config, presence);
  if (llvm::Error preflight_error = validate_security_preflight(config)) {
    return std::move(preflight_error);
  }
  return config;
}

std::string summarize_config(const obfuscation_config& config) {
  std::string output;
  llvm::raw_string_ostream stream(output);

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
  stream << "indirect_dispatch.enabled: "
         << (config.indirect_dispatch.enabled ? "true" : "false") << '\n';
  stream << "indirect_dispatch.max_sites_per_function: "
         << config.indirect_dispatch.max_sites_per_function << '\n';
  stream << "indirect_dispatch.max_switch_targets: "
         << config.indirect_dispatch.max_switch_targets << '\n';
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

  return output;
}

}  // namespace obf
