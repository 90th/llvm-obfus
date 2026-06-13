#pragma once

#include "llvm/ADT/ArrayRef.h"

#include <cstdint>

namespace llvm {
class Constant;
class ConstantDataArray;
class Instruction;
class LLVMContext;
class Value;
}  // namespace llvm

namespace obf::support {

llvm::Value* materialize_constant_expression(llvm::Value* value,
                                             llvm::Instruction* insert_before);

llvm::Constant* create_byte_array_constant(llvm::LLVMContext& context,
                                           llvm::ArrayRef<std::uint8_t> bytes);

std::uint64_t stable_hash_constant(const llvm::Constant& constant);

}  // namespace obf::support
