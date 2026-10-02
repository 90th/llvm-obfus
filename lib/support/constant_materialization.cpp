#include "obf/support/constant_materialization.h"

#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/ErrorHandling.h"
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

void mark_encoded_data(llvm::GlobalVariable& global, encoded_data_kind kind) {
  llvm::LLVMContext& context = global.getContext();
  global.setMetadata(
      "obf.encoded.data",
      llvm::MDNode::get(context,
                        {llvm::ConstantAsMetadata::get(
                             llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 1)),
                         llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
                             llvm::Type::getInt32Ty(context), static_cast<std::uint32_t>(kind)))}));
}

encoded_data_kind get_encoded_data_kind(const llvm::GlobalVariable& global) {
  const llvm::MDNode* metadata = global.getMetadata("obf.encoded.data");
  if (metadata == nullptr) { return encoded_data_kind::none; }
  const auto fail = [&]() {
    llvm::report_fatal_error(llvm::Twine("invalid encoded data provenance in '") +
                            global.getName() + "'");
  };
  const auto* type = llvm::dyn_cast<llvm::ArrayType>(global.getValueType());
  if (!global.hasInitializer() || !global.hasLocalLinkage() || type == nullptr ||
      !type->getElementType()->isIntegerTy(8) || metadata->getNumOperands() != 2) {
    fail();
  }
  const auto read_integer = [&](unsigned index) -> std::uint64_t {
    const auto* constant =
        llvm::dyn_cast_or_null<llvm::ConstantAsMetadata>(metadata->getOperand(index).get());
    const auto* integer =
        constant == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(constant->getValue());
    if (integer == nullptr || !integer->getType()->isIntegerTy(32)) { fail(); }
    return integer->getZExtValue();
  };
  const std::uint64_t version = read_integer(0);
  const std::uint64_t role = read_integer(1);
  if (version != 1 || role == 0 ||
      role > static_cast<std::uint32_t>(encoded_data_kind::global_string)) {
    fail();
  }
  const auto kind = static_cast<encoded_data_kind>(role);
  const bool binary = kind == encoded_data_kind::ciphertext || kind == encoded_data_kind::build_key;
  if (global.isConstant() != binary) { fail(); }
  return kind;
}

}  // namespace obf::support
