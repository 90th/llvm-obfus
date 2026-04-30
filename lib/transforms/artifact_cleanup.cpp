#include "obf/transforms/artifact_cleanup.h"

#include "obf/support/stable_hash.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <string>

namespace obf {
namespace {

std::uint64_t MixSeed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

bool IsEssentialGlobalName(llvm::StringRef name) {
  return name == "__obf_entropy_anchor" ||
         name == "__obf_entropy_anchor_ref" || name.starts_with("llvm.");
}

bool ShouldRenameFunction(const llvm::Function &function) {
  if (function.isDeclaration() || function.getName().empty() ||
      function.getName().starts_with("llvm.")) {
    return false;
  }

  return function.getName().starts_with("__obf_") || function.hasLocalLinkage();
}

bool ShouldRenameGlobal(const llvm::GlobalVariable &global) {
  if (global.isDeclaration() || global.getName().empty() ||
      IsEssentialGlobalName(global.getName())) {
    return false;
  }

  return global.getName().starts_with("__obf_") || global.hasLocalLinkage();
}

bool ShouldRenameAlias(const llvm::GlobalAlias &alias) {
  if (alias.getName().empty() || IsEssentialGlobalName(alias.getName())) {
    return false;
  }

  return alias.getName().starts_with("__obf_") || alias.hasLocalLinkage();
}

std::string BuildObfuscatedName(const llvm::Module &module,
                                llvm::StringRef original_name,
                                std::uint64_t seed_base,
                                std::uint64_t ordinal) {
  std::uint64_t state = seed_base == 0 ? 0x6d2534f1f6c7a29bULL : seed_base;
  state = MixSeed(state, stable_hash_string(module.getName()));
  state = MixSeed(state, stable_hash_string(original_name));
  state = MixSeed(state, ordinal + 1);

  const std::size_t hex_length = 12 + static_cast<std::size_t>(state & 0xfU);
  std::string material;
  material.reserve(hex_length + 16);
  while (material.size() < hex_length) {
    material += llvm::utohexstr(state, /*LowerCase=*/true);
    state = MixSeed(state, material.size() + 1);
  }

  return "_" + material.substr(0, hex_length);
}

template <typename GlobalT>
bool RenameGlobalLike(GlobalT &value, const llvm::Module &module,
                      artifact_cleanup_options options,
                      std::uint64_t ordinal) {
  const std::string original_name = value.getName().str();
  if (original_name.empty()) {
    return false;
  }

  std::uint64_t salt = ordinal;
  while (true) {
    const std::string candidate =
        BuildObfuscatedName(module, original_name, options.seed, salt);
    llvm::GlobalValue *existing = module.getNamedValue(candidate);
    if (existing == nullptr || existing == &value) {
      if (candidate == original_name) {
        return false;
      }

      value.setName(candidate);
      return true;
    }

    ++salt;
  }
}

bool StripLocalNames(llvm::Module &module) {
  bool changed = false;
  for (llvm::Function &function : module) {
    for (llvm::Argument &argument : function.args()) {
      if (!argument.getName().empty()) {
        argument.setName("");
        changed = true;
      }
    }

    for (llvm::BasicBlock &block : function) {
      if (!block.getName().empty()) {
        block.setName("");
        changed = true;
      }

      for (llvm::Instruction &instruction : block) {
        if (!instruction.getName().empty()) {
          instruction.setName("");
          changed = true;
        }
      }
    }
  }

  return changed;
}

} // namespace

bool RunArtifactCleanup(llvm::Module &module,
                        const artifact_cleanup_options &options) {
  bool changed = llvm::StripDebugInfo(module);

  std::uint64_t ordinal = 0;
  for (llvm::GlobalVariable &global : module.globals()) {
    if (ShouldRenameGlobal(global)) {
      changed |= RenameGlobalLike(global, module, options, ordinal++);
    }
  }

  for (llvm::Function &function : module) {
    if (ShouldRenameFunction(function)) {
      changed |= RenameGlobalLike(function, module, options, ordinal++);
    }
  }

  for (llvm::GlobalAlias &alias : module.aliases()) {
    if (ShouldRenameAlias(alias)) {
      changed |= RenameGlobalLike(alias, module, options, ordinal++);
    }
  }

  changed |= StripLocalNames(module);
  return changed;
}

} // namespace obf
