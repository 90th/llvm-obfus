#include "obf/support/affine_helpers.h"

#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"

#include <cstdint>

namespace obf::support {

namespace {

llvm::Constant* constant_apint_to_type(llvm::Type* target_type, const llvm::APInt& value) {
  if (auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    return llvm::ConstantInt::get(integer_type, value.sextOrTrunc(integer_type->getBitWidth()));
  }

  auto* vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto* element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Constant* element =
      llvm::ConstantInt::get(element_type, value.sextOrTrunc(element_type->getBitWidth()));
  return llvm::ConstantVector::getSplat(vector_type->getElementCount(), element);
}

}  // namespace

llvm::APInt make_odd_affine_multiplier(unsigned bit_width, std::uint64_t seed) {
  llvm::APInt multiplier(bit_width, mix_seed(seed, 0xa5a5a5a5f00df00dULL), false, true);
  multiplier |= llvm::APInt(bit_width, 1);
  if (multiplier == llvm::APInt(bit_width, 1)) { multiplier = llvm::APInt(bit_width, 3); }
  return multiplier;
}

llvm::APInt compute_mod_inverse_pow2(const llvm::APInt& odd_value) {
  const unsigned bit_width = odd_value.getBitWidth();
  llvm::APInt inverse(bit_width, 1);
  for (unsigned round = 0; round < bit_width; ++round) {
    inverse *= llvm::APInt(bit_width, 2) - odd_value * inverse;
  }
  return inverse;
}

llvm::APInt make_affine_bias(unsigned bit_width, std::uint64_t seed) {
  return llvm::APInt(bit_width, mix_seed(seed, 0x13579bdf2468ace0ULL), false, true);
}

llvm::Value* build_affine_encode(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& multiplier,
                                 const llvm::APInt& bias,
                                 llvm::StringRef prefix) {
  llvm::Value* scaled = builder.CreateMul(
      value, constant_apint_to_type(value->getType(), multiplier), (prefix + ".mul").str());
  return builder.CreateAdd(
      scaled, constant_apint_to_type(value->getType(), bias), (prefix + ".enc").str());
}

llvm::Value* build_affine_decode(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& inverse,
                                 const llvm::APInt& bias,
                                 llvm::StringRef prefix) {
  llvm::Value* unshifted = builder.CreateSub(
      value, constant_apint_to_type(value->getType(), bias), (prefix + ".sub").str());
  return builder.CreateMul(
      unshifted, constant_apint_to_type(value->getType(), inverse), (prefix + ".dec").str());
}

llvm::Value* rotate_left_scalar(llvm::IRBuilderBase& builder,
                                llvm::Value* value,
                                unsigned amount,
                                llvm::StringRef name_prefix) {
  auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(value->getType());
  if (integer_type == nullptr || integer_type->getBitWidth() <= 1) { return nullptr; }

  const unsigned bit_width = integer_type->getBitWidth();
  amount %= bit_width;
  if (amount == 0) { return value; }

  auto* left_amount = llvm::ConstantInt::get(integer_type, amount);
  auto* right_amount = llvm::ConstantInt::get(integer_type, bit_width - amount);
  llvm::Value* left = builder.CreateShl(value, left_amount, (name_prefix + ".shl").str());
  llvm::Value* right = builder.CreateLShr(value, right_amount, (name_prefix + ".lshr").str());
  return builder.CreateOr(left, right, (name_prefix + ".rot").str());
}

llvm::Value* rotate_right_scalar(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 unsigned amount,
                                 llvm::StringRef name_prefix) {
  auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(value->getType());
  if (integer_type == nullptr || integer_type->getBitWidth() <= 1) { return nullptr; }

  const unsigned bit_width = integer_type->getBitWidth();
  amount %= bit_width;
  if (amount == 0) { return value; }

  auto* right_amount = llvm::ConstantInt::get(integer_type, amount);
  auto* left_amount = llvm::ConstantInt::get(integer_type, bit_width - amount);
  llvm::Value* right = builder.CreateLShr(value, right_amount, (name_prefix + ".lshr").str());
  llvm::Value* left = builder.CreateShl(value, left_amount, (name_prefix + ".shl").str());
  return builder.CreateOr(right, left, (name_prefix + ".rot").str());
}

}  // namespace obf::support
