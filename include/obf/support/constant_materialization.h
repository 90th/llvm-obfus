#pragma once

#include "llvm/ADT/ArrayRef.h"

#include <cstdint>

namespace llvm {
class Constant;
class ConstantDataArray;
class GlobalVariable;
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

enum class encoded_data_kind : std::uint32_t {
  none,
  ciphertext,
  build_key,
  local_string,
  global_string,
};

void mark_encoded_data(llvm::GlobalVariable& global, encoded_data_kind kind);
encoded_data_kind get_encoded_data_kind(const llvm::GlobalVariable& global);

}  // namespace obf::support
