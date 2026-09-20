#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <string>

namespace obf::support {

inline bool is_libc_comparison_name(llvm::StringRef name) {
  return name == "strcmp" || name == "strncmp" || name == "memcmp" || name == "bcmp";
}

inline bool is_valid_libc_comparison_call(const llvm::CallBase& call, bool allow_bcmp = true) {
  const auto* call_inst = llvm::dyn_cast<llvm::CallInst>(&call);
  if (call_inst == nullptr || call_inst->isInlineAsm() || call_inst->isMustTailCall() ||
      call.getNumOperandBundles() != 0 || !call.getType()->isIntegerTy(32)) {
    return false;
  }

  const llvm::Function* callee = call.getCalledFunction();
  if (callee == nullptr || callee->isIntrinsic() || !callee->isDeclaration() ||
      !callee->hasExternalLinkage()) {
    return false;
  }

  const llvm::StringRef callee_name = callee->getName();
  if (!is_libc_comparison_name(callee_name)) {
    return false;
  }
  if (!allow_bcmp && callee_name == "bcmp") {
    return false;
  }

  if (call.getCallingConv() != llvm::CallingConv::C ||
      callee->getCallingConv() != llvm::CallingConv::C) {
    return false;
  }

  const std::string no_builtin_specific = ("no-builtin-" + callee_name).str();
  if (call.isNoBuiltin() || call.hasFnAttr(no_builtin_specific) ||
      call.hasFnAttr("no-builtins") ||
      callee->hasFnAttribute(llvm::Attribute::NoBuiltin) ||
      callee->hasFnAttribute(no_builtin_specific) ||
      callee->hasFnAttribute("no-builtins")) {
    return false;
  }

  const llvm::Function* caller = call.getFunction();
  if (caller != nullptr &&
      (caller->hasFnAttribute(llvm::Attribute::NoBuiltin) ||
       caller->hasFnAttribute(no_builtin_specific) ||
       caller->hasFnAttribute("no-builtins"))) {
    return false;
  }

  const unsigned required_args = (callee_name == "strcmp") ? 2U : 3U;
  if (call.arg_size() != required_args) {
    return false;
  }

  const llvm::Module* module = call.getModule();
  if (module == nullptr) {
    return false;
  }

  const unsigned size_t_bits = module->getDataLayout().getIndexSizeInBits(0);
  const auto has_native_size_t_type = [size_t_bits](llvm::Type* type) {
    const auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(type);
    return integer_type != nullptr && integer_type->getBitWidth() == size_t_bits;
  };

  llvm::FunctionType* callee_ft = callee->getFunctionType();
  if (callee_ft->isVarArg() || !callee_ft->getReturnType()->isIntegerTy(32) ||
      callee_ft->getNumParams() != required_args ||
      !callee_ft->getParamType(0)->isPointerTy() ||
      !callee_ft->getParamType(1)->isPointerTy() ||
      (required_args == 3 && !has_native_size_t_type(callee_ft->getParamType(2)))) {
    return false;
  }

  if (!call.getArgOperand(0)->getType()->isPointerTy() ||
      !call.getArgOperand(1)->getType()->isPointerTy() ||
      (required_args == 3 && !has_native_size_t_type(call.getArgOperand(2)->getType()))) {
    return false;
  }

  auto has_abi_affecting_attr = [](const auto& entity, unsigned arg_idx) {
    return entity.paramHasAttr(arg_idx, llvm::Attribute::ByVal) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::InAlloca) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::Preallocated) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::StructRet) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::ByRef) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::InReg) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::Nest) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::SwiftSelf) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::SwiftAsync) ||
           entity.paramHasAttr(arg_idx, llvm::Attribute::SwiftError);
  };

  auto has_callee_abi_affecting_attr = [](const llvm::Function* fn, unsigned arg_idx) {
    return fn->hasParamAttribute(arg_idx, llvm::Attribute::ByVal) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::InAlloca) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::Preallocated) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::StructRet) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::ByRef) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::InReg) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::Nest) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::SwiftSelf) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::SwiftAsync) ||
           fn->hasParamAttribute(arg_idx, llvm::Attribute::SwiftError);
  };

  for (unsigned arg_idx = 0; arg_idx < 2; ++arg_idx) {
    if (has_abi_affecting_attr(call, arg_idx) ||
        has_callee_abi_affecting_attr(callee, arg_idx)) {
      return false;
    }
  }

  return true;
}

}  // namespace obf::support
