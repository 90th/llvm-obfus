#include "obf/support/constant_materialization.h"

#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

namespace obf::support {

llvm::Value* materialize_constant_expression(llvm::Value* value,
                                             llvm::Instruction* insert_before) {
  auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(value);
  if (expression == nullptr) { return value; }

  llvm::Instruction* materialized = expression->getAsInstruction();
  materialized->insertBefore(insert_before->getIterator());
  for (unsigned operand_index = 0; operand_index < materialized->getNumOperands();
       ++operand_index) {
    materialized->setOperand(
        operand_index,
        materialize_constant_expression(materialized->getOperand(operand_index),
                                        materialized));
  }

  return materialized;
}

llvm::Constant* create_byte_array_constant(llvm::LLVMContext& context,
                                           llvm::ArrayRef<std::uint8_t> bytes) {
  return llvm::ConstantDataArray::get(context, bytes);
}

std::uint64_t stable_hash_constant(const llvm::Constant& constant) {
  std::string printed;
  llvm::raw_string_ostream stream(printed);
  constant.printAsOperand(stream, /*PrintType=*/true);
  stream.flush();
  return stable_hash_string(printed);
}

}  // namespace obf::support
