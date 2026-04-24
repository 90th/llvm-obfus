#include "obf/frontend/config.h"

#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>

LLVM_YAML_IS_SEQUENCE_VECTOR(obf::function_override)
LLVM_YAML_IS_SEQUENCE_VECTOR(obf::target_rule)

namespace llvm::yaml {

template <> struct ScalarEnumerationTraits<obf::protection_level> {
  static void enumeration(IO &io, obf::protection_level &level) {
    io.enumCase(level, "none", obf::protection_level::none);
    io.enumCase(level, "light", obf::protection_level::light);
    io.enumCase(level, "strong", obf::protection_level::strong);
    io.enumCase(level, "vm", obf::protection_level::vm);
    io.enumCase(level, "strong_vm", obf::protection_level::strong_vm);
  }
};

template <> struct MappingTraits<obf::target_rule> {
  static void mapping(IO &io, obf::target_rule &rule) {
    io.mapRequired("match", rule.match);
    io.mapRequired("level", rule.level);
  }
};

template <> struct MappingTraits<obf::function_override> {
  static void mapping(IO &io, obf::function_override &rule) {
    io.mapRequired("name", rule.name);
    io.mapRequired("level", rule.level);
  }
};

template <> struct MappingTraits<obf::block_split_config> {
  static void mapping(IO &io, obf::block_split_config &config) {
    io.mapOptional("max_splits_per_function", config.max_splits_per_function,
                   std::uint32_t{1});
    io.mapOptional("min_instructions_per_block",
                   config.min_instructions_per_block, std::uint32_t{2});
  }
};

template <> struct MappingTraits<obf::string_encoding_config> {
  static void mapping(IO &io, obf::string_encoding_config &config) {
    io.mapOptional("min_string_length", config.min_string_length,
                   std::uint32_t{2});
    io.mapOptional("max_strings_per_module", config.max_strings_per_module,
                   std::uint32_t{64});
    io.mapOptional("prefer_lazy_decode", config.prefer_lazy_decode, true);
    io.mapOptional("allow_ctor_fallback", config.allow_ctor_fallback, true);
    io.mapOptional("strong_vm_allow_global_plaintext",
                   config.strong_vm_allow_global_plaintext, false);
    io.mapOptional("strong_vm_allow_lazy_decode",
                   config.strong_vm_allow_lazy_decode, false);
    io.mapOptional("strong_vm_allow_ctor_fallback",
                   config.strong_vm_allow_ctor_fallback, false);
  }
};

template <> struct MappingTraits<obf::constant_encoding_config> {
  static void mapping(IO &io, obf::constant_encoding_config &config) {
    io.mapOptional("max_constants_per_function",
                   config.max_constants_per_function, std::uint32_t{4});
    io.mapOptional("min_bit_width", config.min_bit_width, std::uint32_t{8});
  }
};

template <> struct MappingTraits<obf::mba_config> {
  static void mapping(IO &io, obf::mba_config &config) {
    io.mapOptional("depth", config.depth, std::uint32_t{1});
  }
};

template <> struct MappingTraits<obf::obfuscation_config> {
  static void mapping(IO &io, obf::obfuscation_config &config) {
    io.mapOptional("seed", config.seed, std::uint64_t{0});
    io.mapOptional("default_level", config.default_level,
                   obf::protection_level::none);
    io.mapOptional("overrides", config.overrides);
    io.mapOptional("targets", config.targets);
    io.mapOptional("block_split", config.block_split);
    io.mapOptional("string_encoding", config.string_encoding);
    io.mapOptional("constant_encoding", config.constant_encoding);
    io.mapOptional("mba", config.mba);
  }
};

} // namespace llvm::yaml

namespace obf {

llvm::Expected<obfuscation_config> load_config_from_file(llvm::StringRef path) {
  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffer_or_error =
      llvm::MemoryBuffer::getFile(path);
  if (!buffer_or_error) {
    return llvm::createStringError(buffer_or_error.getError(),
                                   "failed to read config '%s'",
                                   path.str().c_str());
  }

  llvm::yaml::Input input(buffer_or_error.get()->getBuffer());
  obfuscation_config config;
  input >> config;

  if (input.error()) {
    return llvm::createStringError(input.error(), "failed to parse config '%s'",
                                   path.str().c_str());
  }

  return config;
}

std::string summarize_config(const obfuscation_config &config) {
  std::string output;
  llvm::raw_string_ostream stream(output);

  stream << "seed: " << config.seed << '\n';
  stream << "default_level: " << to_string(config.default_level) << '\n';
  stream << "overrides: " << config.overrides.size() << '\n';
  for (const function_override &override : config.overrides) {
    stream << "  - name: " << override.name << ", level: "
           << to_string(override.level) << '\n';
  }
  stream << "targets: " << config.targets.size() << '\n';

  for (const target_rule &rule : config.targets) {
    stream << "  - match: " << rule.match << ", level: "
           << to_string(rule.level) << '\n';
  }

  stream << "block_split.max_splits_per_function: "
         << config.block_split.max_splits_per_function << '\n';
  stream << "block_split.min_instructions_per_block: "
         << config.block_split.min_instructions_per_block << '\n';
  stream << "string_encoding.min_string_length: "
         << config.string_encoding.min_string_length << '\n';
  stream << "string_encoding.max_strings_per_module: "
         << config.string_encoding.max_strings_per_module << '\n';
  stream << "string_encoding.prefer_lazy_decode: "
         << (config.string_encoding.prefer_lazy_decode ? "true" : "false")
         << '\n';
  stream << "string_encoding.allow_ctor_fallback: "
         << (config.string_encoding.allow_ctor_fallback ? "true" : "false")
         << '\n';
  stream << "string_encoding.strong_vm_allow_global_plaintext: "
         << (config.string_encoding.strong_vm_allow_global_plaintext ? "true"
                                                                    : "false")
         << '\n';
  stream << "string_encoding.strong_vm_allow_lazy_decode: "
         << (config.string_encoding.strong_vm_allow_lazy_decode ? "true"
                                                               : "false")
         << '\n';
  stream << "string_encoding.strong_vm_allow_ctor_fallback: "
         << (config.string_encoding.strong_vm_allow_ctor_fallback ? "true"
                                                                 : "false")
         << '\n';
  stream << "constant_encoding.max_constants_per_function: "
         << config.constant_encoding.max_constants_per_function << '\n';
  stream << "constant_encoding.min_bit_width: "
         << config.constant_encoding.min_bit_width << '\n';
  stream << "mba.depth: " << config.mba.depth << '\n';

  return output;
}

} // namespace obf
