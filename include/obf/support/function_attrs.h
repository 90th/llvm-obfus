#pragma once

#include "llvm/ADT/StringSwitch.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"

namespace obf::support {

inline bool is_preserved_source_function_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute()) {
    return llvm::StringSwitch<bool>(attribute.getKindAsString())
        .Case("approx-func-fp-math", true)
        .Case("branch-protection-pauth-lr", true)
        .Case("branch-target-enforcement", true)
        .Case("denormal-fp-math", true)
        .Case("denormal-fp-math-f32", true)
        .Case("fp-contract", true)
        .Case("frame-pointer", true)
        .Case("less-precise-fpmad", true)
        .Case("no-infs-fp-math", true)
        .Case("no-inline-line-tables", true)
        .Case("no-jump-tables", true)
        .Case("no-nans-fp-math", true)
        .Case("no-signed-zeros-fp-math", true)
        .Case("no-trapping-math", true)
        .Case("probe-stack", true)
        .Case("sign-return-address", true)
        .Case("sign-return-address-key", true)
        .Case("stack-probe-size", true)
        .Case("stack-protector-buffer-size", true)
        .Case("target-cpu", true)
        .Case("target-features", true)
        .Case("tune-cpu", true)
        .Case("tune-features", true)
        .Case("unsafe-fp-math", true)
        .Case("use-soft-float", true)
        .Default(false);
  }

  if (!attribute.hasKindAsEnum()) { return false; }

  switch (attribute.getKindAsEnum()) {
    case llvm::Attribute::Cold:
    case llvm::Attribute::Convergent:
    case llvm::Attribute::DisableSanitizerInstrumentation:
    case llvm::Attribute::Hot:
    case llvm::Attribute::JumpTable:
    case llvm::Attribute::NoBuiltin:
    case llvm::Attribute::NoCfCheck:
    case llvm::Attribute::NoImplicitFloat:
    case llvm::Attribute::NoInline:
    case llvm::Attribute::NoProfile:
    case llvm::Attribute::NoRedZone:
    case llvm::Attribute::NoSanitizeBounds:
    case llvm::Attribute::NoSanitizeCoverage:
    case llvm::Attribute::NoUnwind:
    case llvm::Attribute::NullPointerIsValid:
    case llvm::Attribute::OptForFuzzing:
    case llvm::Attribute::OptimizeNone:
    case llvm::Attribute::SafeStack:
    case llvm::Attribute::SanitizeAddress:
    case llvm::Attribute::SanitizeAllocToken:
    case llvm::Attribute::SanitizeHWAddress:
    case llvm::Attribute::SanitizeMemTag:
    case llvm::Attribute::SanitizeMemory:
    case llvm::Attribute::SanitizeNumericalStability:
    case llvm::Attribute::SanitizeRealtime:
    case llvm::Attribute::SanitizeRealtimeBlocking:
    case llvm::Attribute::SanitizeThread:
    case llvm::Attribute::SanitizeType:
    case llvm::Attribute::ShadowCallStack:
    case llvm::Attribute::SpeculativeLoadHardening:
    case llvm::Attribute::StackProtect:
    case llvm::Attribute::StackProtectReq:
    case llvm::Attribute::StackProtectStrong:
    case llvm::Attribute::StrictFP:
    case llvm::Attribute::UWTable:
    case llvm::Attribute::VScaleRange:
      return true;
    default:
      return false;
  }
}

inline llvm::AttributeList
merge_preserved_source_function_attributes(llvm::AttributeList base,
                                           const llvm::Function& source_function) {
  llvm::LLVMContext& context = source_function.getContext();
  for (llvm::Attribute attribute : source_function.getAttributes().getFnAttrs()) {
    if (!is_preserved_source_function_attribute(attribute)) { continue; }
    if (attribute.isStringAttribute()) {
      base = base.addFnAttribute(
          context, attribute.getKindAsString(), attribute.getValueAsString());
      continue;
    }

    base = base.addFnAttribute(context, attribute);
  }

  return base;
}

inline llvm::AttributeList build_preserved_source_function_attributes(
    const llvm::Function& source_function, const llvm::Function& destination_function) {
  return merge_preserved_source_function_attributes(
      destination_function.getAttributes().removeFnAttributes(destination_function.getContext()),
      source_function);
}

}  // namespace obf::support
