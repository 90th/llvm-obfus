#include "obf/transforms/artifact_cleanup.h"

#include "obf/support/ir_name.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/cfg_state_placeholders.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <tuple>

namespace obf {
namespace {

bool ContainsObfMarker(llvm::StringRef name) { return name.contains("obf"); }

bool IsEssentialGlobalName(llvm::StringRef name, const artifact_cleanup_options& options) {
  if (name.starts_with("llvm.")) { return true; }

  if (!options.strip_release_markers) {
    return name == "__obf_entropy_anchor" || name == "__obf_entropy_anchor_ref";
  }

  return false;
}

bool ShouldRenameFunction(const llvm::Function& function, const artifact_cleanup_options& options) {
  if (function.isDeclaration() || function.getName().empty() ||
      function.getName().starts_with("llvm.")) {
    return false;
  }

  if (options.strip_release_markers) {
    return function.hasLocalLinkage() && ContainsObfMarker(function.getName());
  }

  return function.getName().starts_with("__obf_") || function.hasLocalLinkage();
}

bool ShouldRenameGlobal(const llvm::GlobalVariable& global,
                        const artifact_cleanup_options& options) {
  if (global.isDeclaration() || global.getName().empty() ||
      IsEssentialGlobalName(global.getName(), options)) {
    return false;
  }

  if (options.strip_release_markers) {
    return global.hasLocalLinkage() && ContainsObfMarker(global.getName());
  }

  return global.getName().starts_with("__obf_") || global.hasLocalLinkage();
}

bool ShouldRenameAlias(const llvm::GlobalAlias& alias, const artifact_cleanup_options& options) {
  if (alias.getName().empty() || IsEssentialGlobalName(alias.getName(), options)) { return false; }

  if (options.strip_release_markers) {
    return alias.hasLocalLinkage() && ContainsObfMarker(alias.getName());
  }

  return alias.getName().starts_with("__obf_") || alias.hasLocalLinkage();
}

template <typename GlobalT>
bool RenameGlobalLike(GlobalT& value,
                      const llvm::Module& module,
                      artifact_cleanup_options options,
                      std::uint64_t ordinal) {
  const std::string original_name = value.getName().str();
  if (original_name.empty()) { return false; }

  std::uint64_t salt = ordinal;
  while (true) {
    const std::string candidate = obf::support::obfuscated_symbol_name(
        module.getName(), original_name, options.seed, salt);
    llvm::GlobalValue* existing = module.getNamedValue(candidate);
    if (existing == nullptr || existing == &value) {
      if (candidate == original_name) { return false; }

      value.setName(candidate);
      return true;
    }

    ++salt;
  }
}

bool StripLocalNames(llvm::Module& module) {
  bool changed = false;
  for (llvm::Function& function : module) {
    for (llvm::Argument& argument : function.args()) {
      if (!argument.getName().empty()) {
        argument.setName("");
        changed = true;
      }
    }

    for (llvm::BasicBlock& block : function) {
      if (!block.getName().empty()) {
        block.setName("");
        changed = true;
      }

      for (llvm::Instruction& instruction : block) {
        if (!instruction.getName().empty()) {
          instruction.setName("");
          changed = true;
        }
      }
    }
  }

  return changed;
}

bool ShouldStripReleaseMarkerAttribute(llvm::Attribute attribute) {
  if (!attribute.isStringAttribute()) { return false; }

  const llvm::StringRef kind = attribute.getKindAsString();
  return kind.starts_with("obf.") || kind.starts_with("vm.");
}

bool StripReleaseMarkerFunctionAttributes(llvm::Module& module) {
  bool changed = false;
  for (llvm::Function& function : module) {
    llvm::SmallVector<std::string, 8> attributes_to_remove;
    for (llvm::Attribute attribute : function.getAttributes().getFnAttrs()) {
      if (!ShouldStripReleaseMarkerAttribute(attribute)) { continue; }
      attributes_to_remove.push_back(attribute.getKindAsString().str());
    }

    for (const std::string& attribute_name : attributes_to_remove) {
      function.removeFnAttr(attribute_name);
      changed = true;
    }
  }

  return changed;
}

void CollectMetadataGlobals(llvm::Constant* constant,
                            llvm::SmallPtrSetImpl<llvm::Constant*>& visited,
                            llvm::SmallPtrSetImpl<llvm::GlobalVariable*>& globals) {
  if (constant == nullptr || !visited.insert(constant).second) { return; }

  if (auto* global = llvm::dyn_cast<llvm::GlobalVariable>(constant->stripPointerCasts())) {
    if (global->getSection() == "llvm.metadata") { globals.insert(global); }
    return;
  }

  for (llvm::Value* operand : constant->operands()) {
    auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
    if (operand_constant == nullptr) { continue; }
    CollectMetadataGlobals(operand_constant, visited, globals);
  }
}

bool StripGlobalAnnotations(llvm::Module& module) {
  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr) { return false; }

  llvm::SmallPtrSet<llvm::Constant*, 32> visited;
  llvm::SmallPtrSet<llvm::GlobalVariable*, 8> metadata_globals;
  if (annotations->hasInitializer()) {
    CollectMetadataGlobals(annotations->getInitializer(), visited, metadata_globals);
  }

  llvm::SmallPtrSet<llvm::GlobalValue*, 8> values_to_remove;
  values_to_remove.insert(annotations);
  for (llvm::GlobalVariable* global : metadata_globals) { values_to_remove.insert(global); }

  llvm::removeFromUsedLists(module, [&](llvm::Constant* constant) {
    if (constant == nullptr) { return false; }
    auto* value = llvm::dyn_cast<llvm::GlobalValue>(constant->stripPointerCasts());
    return value != nullptr && values_to_remove.contains(value);
  });

  bool changed = false;
  if (annotations->use_empty()) {
    annotations->eraseFromParent();
    changed = true;
  }

  for (llvm::GlobalVariable* global : metadata_globals) {
    if (global == nullptr || !global->use_empty()) { continue; }
    global->eraseFromParent();
    changed = true;
  }

  return changed;
}

bool IsPublicReleaseMarkerSymbol(const llvm::GlobalValue& value) {
  return value.hasExternalLinkage() && !value.getName().empty() && !value.getName().starts_with("llvm.") &&
         ContainsObfMarker(value.getName());
}

[[noreturn]] void ReportReleaseMarkerFailure(llvm::StringRef kind, llvm::StringRef name) {
  std::string message = "release marker stripping failure: external ";
  message += kind.str();
  message += ' ';
  message += name.str();
  message += " contains obf";
  llvm::report_fatal_error(llvm::StringRef(message));
}

[[noreturn]] void ReportCfgPlaceholderFailure(llvm::StringRef name) {
  std::string message = "release marker stripping failure: cfg placeholder ";
  message += name.str();
  message += " survived final cleanup";
  llvm::report_fatal_error(llvm::StringRef(message));
}

void EnforceCfgPlaceholderAbsence(llvm::Module& module) {
  for (llvm::Function& function : module) {
    if (function.getName() == kCfgStatePlaceholderName ||
        function.getName() == kExpectedCfgStatePlaceholderName) {
      ReportCfgPlaceholderFailure(function.getName());
    }
  }
}

void EnforcePublicReleaseMarkerGate(llvm::Module& module) {
  llvm::SmallVector<std::tuple<std::string, std::string>, 8> offenders;

  for (llvm::Function& function : module) {
    if (IsPublicReleaseMarkerSymbol(function)) {
      offenders.emplace_back(function.getName().str(), "function");
    }
  }

  for (llvm::GlobalVariable& global : module.globals()) {
    if (IsPublicReleaseMarkerSymbol(global)) { offenders.emplace_back(global.getName().str(), "global"); }
  }

  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (IsPublicReleaseMarkerSymbol(alias)) { offenders.emplace_back(alias.getName().str(), "alias"); }
  }

  if (offenders.empty()) { return; }

  std::sort(offenders.begin(), offenders.end(), [](const auto& lhs, const auto& rhs) {
    return std::tie(std::get<0>(lhs), std::get<1>(lhs)) <
           std::tie(std::get<0>(rhs), std::get<1>(rhs));
  });
  ReportReleaseMarkerFailure(std::get<1>(offenders.front()), std::get<0>(offenders.front()));
}

}  // namespace

bool RunArtifactCleanup(llvm::Module& module, const artifact_cleanup_options& options) {
  bool changed = llvm::StripDebugInfo(module);

  if (options.strip_release_markers) {
    EnforceCfgPlaceholderAbsence(module);
    EnforcePublicReleaseMarkerGate(module);
    changed |= StripReleaseMarkerFunctionAttributes(module);
    changed |= StripGlobalAnnotations(module);
  }

  std::uint64_t ordinal = 0;
  for (llvm::GlobalVariable& global : module.globals()) {
    if (ShouldRenameGlobal(global, options)) {
      changed |= RenameGlobalLike(global, module, options, ordinal++);
    }
  }

  for (llvm::Function& function : module) {
    if (ShouldRenameFunction(function, options)) {
      changed |= RenameGlobalLike(function, module, options, ordinal++);
    }
  }

  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (ShouldRenameAlias(alias, options)) {
      changed |= RenameGlobalLike(alias, module, options, ordinal++);
    }
  }

  changed |= StripLocalNames(module);
  return changed;
}

}  // namespace obf
