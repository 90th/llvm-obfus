#pragma once

namespace llvm {
class Constant;
class Function;
class GlobalVariable;
class Value;
template <typename T>
class SmallVectorImpl;
}  // namespace llvm

namespace obf::support {

void add_unique_function(llvm::SmallVectorImpl<llvm::Function*>& list, llvm::Function* fn);
bool operand_references_value(const llvm::Value* operand, const llvm::Value& target);
bool constant_references_value(const llvm::Constant* constant, const llvm::Value& target);
bool operand_references_global(llvm::Value* value, const llvm::GlobalVariable& global);

}  // namespace obf::support
