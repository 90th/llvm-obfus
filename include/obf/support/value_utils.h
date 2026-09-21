#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm {
class Constant;
class Function;
class GlobalVariable;
class Value;
template <typename T>
class SmallVectorImpl;
}  // namespace llvm

namespace obf::support {

struct stabilized_value {
  llvm::Value* value = nullptr;
  llvm::Value* poison_guard = nullptr;
};

void add_unique_function(llvm::SmallVectorImpl<llvm::Function*>& list, llvm::Function* fn);
bool operand_references_value(const llvm::Value* operand, const llvm::Value& target);
bool constant_references_value(const llvm::Constant* constant, const llvm::Value& target);
bool operand_references_global(llvm::Value* value, const llvm::GlobalVariable& global);

stabilized_value
stabilize_value_for_reuse(llvm::IRBuilder<>& builder, llvm::Value* value, llvm::StringRef name);
llvm::Value* restore_poison_from_stabilized_values(llvm::IRBuilder<>& builder,
                                                   llvm::Value* result,
                                                   llvm::ArrayRef<stabilized_value> values,
                                                   llvm::StringRef name);

}  // namespace obf::support
