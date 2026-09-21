#include "obf/support/value_utils.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Value.h"

#include <algorithm>

namespace obf::support {
stabilized_value
stabilize_value_for_reuse(llvm::IRBuilder<>& builder, llvm::Value* value, llvm::StringRef name) {
  if (llvm::isGuaranteedNotToBeUndef(value)) { return {.value = value}; }

  llvm::Value* stable = llvm::isa<llvm::FreezeInst>(value)
                            ? value
                            : builder.CreateFreeze(value, (name + ".stable").str());
  if (llvm::isGuaranteedNotToBePoison(value)) { return {.value = stable}; }

  llvm::Value* poison_guard = builder.CreateMul(
      value, llvm::Constant::getNullValue(value->getType()), (name + ".poison").str());
  return {.value = stable, .poison_guard = poison_guard};
}

llvm::Value* restore_poison_from_stabilized_values(llvm::IRBuilder<>& builder,
                                                   llvm::Value* result,
                                                   llvm::ArrayRef<stabilized_value> values,
                                                   llvm::StringRef name) {
  for (const stabilized_value& value : values) {
    if (value.poison_guard == nullptr) { continue; }
    result = builder.CreateOr(result, value.poison_guard, (name + ".poison").str());
  }
  return result;
}

void add_unique_function(llvm::SmallVectorImpl<llvm::Function*>& functions,
                         llvm::Function* function) {
  if (function == nullptr) { return; }
  if (std::find(functions.begin(), functions.end(), function) != functions.end()) { return; }
  functions.push_back(function);
}

bool constant_references_value(const llvm::Constant* constant, const llvm::Value& value) {
  if (constant == &value) { return true; }

  for (const llvm::Value* operand : constant->operands()) {
    if (operand == &value) { return true; }
    const auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
    if (operand_constant != nullptr && constant_references_value(operand_constant, value)) {
      return true;
    }
  }

  return false;
}

bool operand_references_value(const llvm::Value* operand, const llvm::Value& value) {
  if (operand == nullptr) { return false; }
  if (operand == &value) { return true; }

  const auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
  if (operand_constant != nullptr && constant_references_value(operand_constant, value)) {
    return true;
  }

  llvm::Value* underlying = llvm::getUnderlyingObject(const_cast<llvm::Value*>(operand));
  return underlying == &value;
}

bool operand_references_global(llvm::Value* operand, const llvm::GlobalVariable& global) {
  if (operand == nullptr) { return false; }

  llvm::Value* underlying = llvm::getUnderlyingObject(operand);
  return underlying == &global;
}

}  // namespace obf::support
