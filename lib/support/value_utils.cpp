#include "obf/support/value_utils.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Value.h"

#include <algorithm>

namespace obf::support {

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
