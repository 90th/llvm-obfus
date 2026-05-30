#include "obf/transforms/mba.h"

#include "obf/support/runtime_abi_generated.h"
#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/FormatVariadic.h"

#include <algorithm>
#include <cstdint>

namespace obf::mba {

namespace {

enum class opaque_zero_shape {
  xor_pair,
  add_sub_pair,
  sub_pair,
  rotate_xor_pair,
  cmp_select_pair,
  affine_cancel_pair,
  affine_self_diff,
  linear_equiv_pair,
  polynomial_binomial_pair,
  polynomial_affine_pair,
};

enum class add_shape {
  or_and,
  xor_carry,
  affine_xor_carry,
  xor_shifted_carry,
};

enum class sub_shape {
  xor_borrow,
  lhs_rhs_only,
  affine_xor_borrow,
  ones_complement_add,
};

enum class xor_shape {
  or_and_sub,
  disjoint_sum,
  affine_or_and_sub,
  sum_minus_carry,
};

enum class opaque_integer_shape {
  entangled_constant,
  xor_split,
  add_split,
  affine_decode,
  zero_add,
};

enum class entangle_shape {
  xor_zero,
  add_zero,
  sub_zero,
  xor_masked_pair,
  add_sub_masked_pair,
};

enum class entropy_thunk_shape {
  direct,
  swap_twice,
  xor_neutral,
  add_sub_neutral,
  select_neutral,
};

enum class entropy_accessor_variant {
  direct,
  stack_roundtrip,
  split_recombine,
  xor_neutral,
  add_sub_neutral,
};

struct mba_budget {
  std::uint32_t max_ir_instructions = 16;
  std::uint32_t max_terms = 4;
  std::uint32_t max_mul_terms = 0;
};

struct mba_features {
  bool enable_linear_permutations = false;
  bool enable_affine_wrappers = true;
  bool enable_polynomial_zeros = false;
  bool enable_multiplication = false;
  bool enable_division_constants = false;
  bool enable_simplifier_barriers = true;
};

std::uint32_t clamped_depth(const builder_context& context) {
  return std::min(context.depth, max_mba_depth);
}

mba_budget derive_budget(const builder_context& context) {
  switch (clamped_depth(context)) {
    case 0:
      return {.max_ir_instructions = 0, .max_terms = 1, .max_mul_terms = 0};
    case 1:
      return {.max_ir_instructions = 64, .max_terms = 4, .max_mul_terms = 0};
    case 2:
      return {.max_ir_instructions = 128, .max_terms = 6, .max_mul_terms = 2};
    case 3:
      return {.max_ir_instructions = 192, .max_terms = 8, .max_mul_terms = 3};
    case 4:
      return {.max_ir_instructions = 256, .max_terms = 10, .max_mul_terms = 4};
    default:
      return {.max_ir_instructions = 320, .max_terms = 12, .max_mul_terms = 4};
  }
}

mba_features derive_features(const builder_context& context) {
  const std::uint32_t depth = clamped_depth(context);
  return {.enable_linear_permutations = depth >= 2,
          .enable_affine_wrappers = depth >= 1,
          .enable_polynomial_zeros = depth >= 3,
          .enable_multiplication = depth >= 3,
          .enable_division_constants = depth >= 3,
          .enable_simplifier_barriers = true};
}

bool has_budget(const builder_context& context, std::uint32_t instruction_cost) {
  return derive_budget(context).max_ir_instructions >= instruction_cost;
}

unsigned get_integer_bit_width(const llvm::Type* type) {
  if (const auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(type)) {
    return integer_type->getBitWidth();
  }

  const auto* vector_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
  if (vector_type == nullptr) { return 0; }
  const auto* element_type = llvm::dyn_cast<llvm::IntegerType>(vector_type->getElementType());
  return element_type == nullptr ? 0 : element_type->getBitWidth();
}

bool supports_shift_by_one(const llvm::Type* type) { return get_integer_bit_width(type) > 1; }

std::uint64_t derive_shape_seed(const builder_context& context,
                                llvm::StringRef family,
                                std::uint64_t salt,
                                const llvm::Type* type = nullptr,
                                std::uint32_t remaining_depth = 0,
                                std::uint64_t shape_ordinal = 0) {
  std::uint64_t seed = context.seed_base;
  seed = mix_seed(seed, stable_hash_string(family));
  seed = mix_seed(seed, salt);
  seed = mix_seed(seed, get_integer_bit_width(type));
  seed = mix_seed(seed, remaining_depth);
  seed = mix_seed(seed, shape_ordinal);
  return seed;
}

opaque_zero_shape select_opaque_zero_shape(const builder_context& context, std::uint64_t salt) {
  const mba_features features = derive_features(context);
  const bool enable_linear = features.enable_linear_permutations && has_budget(context, 8);
  const bool enable_polynomial = features.enable_polynomial_zeros && has_budget(context, 16);

  if (enable_polynomial) {
    switch (mix_seed(context.seed_base, salt ^ 0x4f7c2d1b9a031ULL) % 10U) {
      case 0:
        return opaque_zero_shape::xor_pair;
      case 1:
        return opaque_zero_shape::add_sub_pair;
      case 2:
        return opaque_zero_shape::sub_pair;
      case 3:
        return opaque_zero_shape::rotate_xor_pair;
      case 4:
        return opaque_zero_shape::cmp_select_pair;
      case 5:
        return opaque_zero_shape::affine_cancel_pair;
      case 6:
        return opaque_zero_shape::affine_self_diff;
      case 7:
        return opaque_zero_shape::linear_equiv_pair;
      case 8:
        return opaque_zero_shape::polynomial_binomial_pair;
      default:
        return opaque_zero_shape::polynomial_affine_pair;
    }
  }

  if (enable_linear) {
    switch (mix_seed(context.seed_base, salt ^ 0x4f7c2d1b9a031ULL) % 8U) {
      case 0:
        return opaque_zero_shape::xor_pair;
      case 1:
        return opaque_zero_shape::add_sub_pair;
      case 2:
        return opaque_zero_shape::sub_pair;
      case 3:
        return opaque_zero_shape::rotate_xor_pair;
      case 4:
        return opaque_zero_shape::cmp_select_pair;
      case 5:
        return opaque_zero_shape::affine_cancel_pair;
      case 6:
        return opaque_zero_shape::affine_self_diff;
      default:
        return opaque_zero_shape::linear_equiv_pair;
    }
  }

  switch (mix_seed(context.seed_base, salt ^ 0x4f7c2d1b9a031ULL) % 7U) {
    case 0:
      return opaque_zero_shape::xor_pair;
    case 1:
      return opaque_zero_shape::add_sub_pair;
    case 2:
      return opaque_zero_shape::sub_pair;
    case 3:
      return opaque_zero_shape::rotate_xor_pair;
    case 4:
      return opaque_zero_shape::cmp_select_pair;
    case 5:
      return opaque_zero_shape::affine_cancel_pair;
    default:
      return opaque_zero_shape::affine_self_diff;
  }
}

add_shape select_add_shape(const builder_context& context, std::uint64_t salt) {
  const mba_features features = derive_features(context);
  const std::uint64_t shape_count =
      features.enable_linear_permutations && has_budget(context, 6) ? 4U : 3U;
  switch (mix_seed(context.seed_base, salt ^ 0x61c8864680b583ebULL) % shape_count) {
    case 0:
      return add_shape::or_and;
    case 1:
      return add_shape::xor_carry;
    case 2:
      return add_shape::affine_xor_carry;
    default:
      return add_shape::xor_shifted_carry;
  }
}

sub_shape select_sub_shape(const builder_context& context, std::uint64_t salt) {
  const mba_features features = derive_features(context);
  const std::uint64_t shape_count =
      features.enable_linear_permutations && has_budget(context, 5) ? 4U : 3U;
  switch (mix_seed(context.seed_base, salt ^ 0x94d049bb133111ebULL) % shape_count) {
    case 0:
      return sub_shape::xor_borrow;
    case 1:
      return sub_shape::lhs_rhs_only;
    case 2:
      return sub_shape::affine_xor_borrow;
    default:
      return sub_shape::ones_complement_add;
  }
}

xor_shape select_xor_shape(const builder_context& context, std::uint64_t salt) {
  const mba_features features = derive_features(context);
  const std::uint64_t shape_count =
      features.enable_linear_permutations && has_budget(context, 7) ? 4U : 3U;
  switch (mix_seed(context.seed_base, salt ^ 0xdbe6d5d5fe4cce2fULL) % shape_count) {
    case 0:
      return xor_shape::or_and_sub;
    case 1:
      return xor_shape::disjoint_sum;
    case 2:
      return xor_shape::affine_or_and_sub;
    default:
      return xor_shape::sum_minus_carry;
  }
}

opaque_integer_shape select_opaque_integer_shape(const builder_context& context,
                                                 std::uint64_t salt,
                                                 llvm::IntegerType* type) {
  const mba_features features = derive_features(context);
  std::uint64_t shape_count =
      features.enable_linear_permutations && has_budget(context, 8) ? 3U : 1U;
  if (features.enable_linear_permutations && features.enable_affine_wrappers &&
      type->getBitWidth() > 1 && has_budget(context, 10)) {
    shape_count = std::max<std::uint64_t>(shape_count, 4U);
  }
  if (features.enable_linear_permutations && has_budget(context, 12)) {
    shape_count = std::max<std::uint64_t>(shape_count, 5U);
  }

  switch (derive_shape_seed(context, "mba.opaque_integer", salt, type) % shape_count) {
    case 0:
      return opaque_integer_shape::entangled_constant;
    case 1:
      return opaque_integer_shape::xor_split;
    case 2:
      return opaque_integer_shape::add_split;
    case 3:
      return opaque_integer_shape::affine_decode;
    default:
      return opaque_integer_shape::zero_add;
  }
}

entangle_shape select_entangle_shape(const builder_context& context, std::uint64_t salt) {
  switch (mix_seed(context.seed_base, salt ^ 0x25b7e151628aed2bULL) % 5U) {
    case 0:
      return entangle_shape::xor_zero;
    case 1:
      return entangle_shape::add_zero;
    case 2:
      return entangle_shape::sub_zero;
    case 3:
      return entangle_shape::xor_masked_pair;
    default:
      return entangle_shape::add_sub_masked_pair;
  }
}

entropy_thunk_shape select_entropy_thunk_shape(llvm::Function& owner,
                                               const builder_context& context,
                                               std::uint64_t salt) {
  std::uint64_t selector = context.seed_base;
  selector = mix_seed(selector, stable_hash_string(owner.getName()));
  selector = mix_seed(selector, salt ^ 0x64ef22d5c31a91b7ULL);
  switch (selector % 5U) {
    case 0:
      return entropy_thunk_shape::direct;
    case 1:
      return entropy_thunk_shape::swap_twice;
    case 2:
      return entropy_thunk_shape::xor_neutral;
    case 3:
      return entropy_thunk_shape::add_sub_neutral;
    default:
      return entropy_thunk_shape::select_neutral;
  }
}

entropy_accessor_variant select_entropy_accessor_variant(llvm::Function& owner,
                                                         const builder_context& context,
                                                         std::uint64_t salt) {
  std::uint64_t selector = context.seed_base;
  selector = mix_seed(selector, stable_hash_string(owner.getName()));
  selector = mix_seed(selector, salt ^ 0x45c0a77e91d5b33dULL);
  switch (selector % 5U) {
    case 0:
      return entropy_accessor_variant::direct;
    case 1:
      return entropy_accessor_variant::stack_roundtrip;
    case 2:
      return entropy_accessor_variant::split_recombine;
    case 3:
      return entropy_accessor_variant::xor_neutral;
    default:
      return entropy_accessor_variant::add_sub_neutral;
  }
}

std::uint64_t derive_function_seed(const llvm::Function& function,
                                   llvm::StringRef prefix,
                                   std::uint64_t seed_base) {
  std::uint64_t seed = seed_base;
  seed = mix_seed(seed, stable_hash_string(function.getName()));
  seed = mix_seed(seed, stable_hash_string(prefix));
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

bool is_supported_type(const llvm::Type* type) {
  if (type->isIntegerTy()) { return true; }

  const auto* vector_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
  return vector_type != nullptr && vector_type->getElementType()->isIntegerTy();
}

llvm::Value* cast_i64_to_type(llvm::IRBuilder<>& builder,
                              llvm::Value* value64,
                              llvm::Type* target_type,
                              llvm::StringRef name_prefix) {
  if (auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    if (integer_type->getBitWidth() < 64) {
      return builder.CreateTrunc(value64, integer_type, (name_prefix + ".trunc").str());
    }

    if (integer_type->getBitWidth() > 64) {
      return builder.CreateZExt(value64, integer_type, (name_prefix + ".zext").str());
    }

    return value64;
  }

  auto* vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto* element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Value* element_value = value64;
  if (element_type->getBitWidth() < 64) {
    element_value = builder.CreateTrunc(value64, element_type, (name_prefix + ".elt.trunc").str());
  } else if (element_type->getBitWidth() > 64) {
    element_value = builder.CreateZExt(value64, element_type, (name_prefix + ".elt.zext").str());
  }

  return builder.CreateVectorSplat(
      vector_type->getElementCount(), element_value, (name_prefix + ".vec").str());
}

llvm::Constant* constant_i64_to_type(llvm::Type* target_type, std::uint64_t word) {
  if (auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    return llvm::ConstantInt::get(integer_type,
                                  llvm::APInt(integer_type->getBitWidth(), word, false, true));
  }

  auto* vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto* element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Constant* element = llvm::ConstantInt::get(
      element_type, llvm::APInt(element_type->getBitWidth(), word, false, true));
  return llvm::ConstantVector::getSplat(vector_type->getElementCount(), element);
}

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

bool is_affine_scalar_type(const llvm::Type* target_type) {
  const auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type);
  return integer_type != nullptr && integer_type->getBitWidth() > 1;
}

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

llvm::Value* build_affine_encode(llvm::IRBuilder<>& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& multiplier,
                                 const llvm::APInt& bias,
                                 llvm::StringRef prefix) {
  llvm::Value* scaled = builder.CreateMul(
      value, constant_apint_to_type(value->getType(), multiplier), (prefix + ".mul").str());
  return builder.CreateAdd(
      scaled, constant_apint_to_type(value->getType(), bias), (prefix + ".enc").str());
}

llvm::Value* build_affine_decode(llvm::IRBuilder<>& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& inverse,
                                 const llvm::APInt& bias,
                                 llvm::StringRef prefix) {
  llvm::Value* unshifted = builder.CreateSub(
      value, constant_apint_to_type(value->getType(), bias), (prefix + ".sub").str());
  return builder.CreateMul(
      unshifted, constant_apint_to_type(value->getType(), inverse), (prefix + ".dec").str());
}

llvm::Value* rotate_left_scalar(llvm::IRBuilder<>& builder,
                                llvm::Value* value,
                                unsigned amount,
                                llvm::StringRef name_prefix) {
  auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(value->getType());
  if (integer_type == nullptr || integer_type->getBitWidth() <= 1) { return nullptr; }

  const unsigned bit_width = integer_type->getBitWidth();
  amount %= bit_width;
  if (amount == 0) { amount = 1; }

  auto* left_amount = llvm::ConstantInt::get(integer_type, amount);
  auto* right_amount = llvm::ConstantInt::get(integer_type, bit_width - amount);
  llvm::Value* left = builder.CreateShl(value, left_amount, (name_prefix + ".shl").str());
  llvm::Value* right = builder.CreateLShr(value, right_amount, (name_prefix + ".lshr").str());
  return builder.CreateOr(left, right, (name_prefix + ".rot").str());
}

struct entropy_pair {
  llvm::Value* direct = nullptr;
  llvm::Value* indirect = nullptr;
};

std::uint64_t derive_entropy_thunk_id(llvm::Function& owner,
                                      const builder_context& context,
                                      std::uint64_t salt,
                                      entropy_thunk_shape shape) {
  std::uint64_t id = context.seed_base;
  id = mix_seed(id, stable_hash_string(owner.getName()));
  id = mix_seed(id, salt);
  id = mix_seed(id, static_cast<std::uint64_t>(shape));
  return id == 0 ? 0xa55aa55aa55aa55aULL : id;
}

std::uint64_t derive_entropy_thunk_constant(llvm::Function& owner,
                                            const builder_context& context,
                                            std::uint64_t salt,
                                            std::uint64_t family_salt) {
  std::uint64_t value = context.seed_base;
  value = mix_seed(value, stable_hash_string(owner.getName()));
  value = mix_seed(value, salt ^ family_salt);
  return value == 0 ? 0x9e3779b97f4a7c15ULL : value;
}

llvm::Value* build_entropy_thunk_xor_neutral(llvm::IRBuilder<>& builder,
                                             llvm::Function& owner,
                                             const builder_context& context,
                                             std::uint64_t salt,
                                             llvm::Value* pair,
                                             llvm::StringRef prefix) {
  llvm::Type* i64_type = llvm::Type::getInt64Ty(builder.getContext());
  llvm::Value* direct = builder.CreateExtractValue(pair, {0}, (prefix + ".direct").str());
  llvm::Value* indirect = builder.CreateExtractValue(pair, {1}, (prefix + ".indirect").str());
  llvm::Value* key = llvm::ConstantInt::get(
      i64_type, derive_entropy_thunk_constant(owner, context, salt, 0x135700ULL));
  llvm::Value* direct_masked = builder.CreateXor(direct, key, (prefix + ".direct.masked").str());
  llvm::Value* direct_real = builder.CreateXor(direct_masked, key, (prefix + ".direct.real").str());
  llvm::Value* indirect_masked =
      builder.CreateXor(indirect, key, (prefix + ".indirect.masked").str());
  llvm::Value* indirect_real =
      builder.CreateXor(indirect_masked, key, (prefix + ".indirect.real").str());
  llvm::Value* result = llvm::UndefValue::get(pair->getType());
  result = builder.CreateInsertValue(result, direct_real, {0}, (prefix + ".insert.direct").str());
  return builder.CreateInsertValue(result, indirect_real, {1}, (prefix + ".insert.indirect").str());
}

llvm::StringRef get_entropy_accessor_name(entropy_accessor_variant variant) {
  switch (variant) {
    case entropy_accessor_variant::direct:
      return OBF_RT_LOAD_ENTROPY_PAIR_STR;
    case entropy_accessor_variant::stack_roundtrip:
      return OBF_RT_LOAD_ENTROPY_PAIR_V1_STR;
    case entropy_accessor_variant::split_recombine:
      return OBF_RT_LOAD_ENTROPY_PAIR_V2_STR;
    case entropy_accessor_variant::xor_neutral:
      return OBF_RT_LOAD_ENTROPY_PAIR_V3_STR;
    case entropy_accessor_variant::add_sub_neutral:
      return OBF_RT_LOAD_ENTROPY_PAIR_V4_STR;
  }

  llvm_unreachable("unknown entropy accessor variant");
}

llvm::Function* get_or_create_entropy_thunk(llvm::Module& module,
                                            llvm::Function& owner,
                                            llvm::Function& entropy_anchor,
                                            const builder_context& context,
                                            std::uint64_t salt) {
  entropy_thunk_shape shape = select_entropy_thunk_shape(owner, context, salt);
  const std::uint64_t thunk_id = derive_entropy_thunk_id(owner, context, salt, shape);
  const std::string thunk_name = llvm::formatv("__obf_entropy_thunk_{0:x}", thunk_id).str();
  if (llvm::Function* existing = module.getFunction(thunk_name)) { return existing; }

  auto* thunk = llvm::Function::Create(
      entropy_anchor.getFunctionType(), llvm::GlobalValue::InternalLinkage, thunk_name, module);
  thunk->setDSOLocal(true);
  thunk->addFnAttr(llvm::Attribute::NoInline);

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(module.getContext(), "entry", thunk);
  llvm::IRBuilder<> builder(entry);
  const char* prefix = "entropy.thunk.direct";
  if (shape == entropy_thunk_shape::swap_twice) {
    prefix = "entropy.thunk.swap";
  } else if (shape == entropy_thunk_shape::xor_neutral) {
    prefix = "entropy.thunk.xor";
  } else if (shape == entropy_thunk_shape::add_sub_neutral) {
    prefix = "entropy.thunk.addsub";
  } else if (shape == entropy_thunk_shape::select_neutral) {
    prefix = "entropy.thunk.select";
  }

  llvm::Value* pair = builder.CreateCall(
      entropy_anchor.getFunctionType(), &entropy_anchor, {}, std::string(prefix) + ".call");
  switch (shape) {
    case entropy_thunk_shape::direct:
      builder.CreateRet(pair);
      break;
    case entropy_thunk_shape::swap_twice: {
      llvm::Value* direct = builder.CreateExtractValue(pair, {0}, "entropy.thunk.swap.direct");
      llvm::Value* indirect = builder.CreateExtractValue(pair, {1}, "entropy.thunk.swap.indirect");
      llvm::Value* swapped = llvm::UndefValue::get(pair->getType());
      swapped = builder.CreateInsertValue(swapped, indirect, {0}, "entropy.thunk.swap.first");
      swapped = builder.CreateInsertValue(swapped, direct, {1}, "entropy.thunk.swap.second");
      llvm::Value* restored_direct =
          builder.CreateExtractValue(swapped, {1}, "entropy.thunk.swap.restore.direct");
      llvm::Value* restored_indirect =
          builder.CreateExtractValue(swapped, {0}, "entropy.thunk.swap.restore.indirect");
      llvm::Value* restored = llvm::UndefValue::get(pair->getType());
      restored = builder.CreateInsertValue(
          restored, restored_direct, {0}, "entropy.thunk.swap.restored.direct");
      restored = builder.CreateInsertValue(
          restored, restored_indirect, {1}, "entropy.thunk.swap.restored.indirect");
      builder.CreateRet(restored);
      break;
    }
    case entropy_thunk_shape::xor_neutral:
      builder.CreateRet(build_entropy_thunk_xor_neutral(
          builder, owner, context, salt, pair, "entropy.thunk.xor"));
      break;
    case entropy_thunk_shape::add_sub_neutral: {
      llvm::Type* i64_type = llvm::Type::getInt64Ty(module.getContext());
      llvm::Value* direct = builder.CreateExtractValue(pair, {0}, "entropy.thunk.addsub.direct");
      llvm::Value* indirect =
          builder.CreateExtractValue(pair, {1}, "entropy.thunk.addsub.indirect");
      llvm::Value* key = llvm::ConstantInt::get(
          i64_type, derive_entropy_thunk_constant(owner, context, salt, 0x246800ULL));
      llvm::Value* direct_biased =
          builder.CreateAdd(direct, key, "entropy.thunk.addsub.direct.biased");
      llvm::Value* direct_real =
          builder.CreateSub(direct_biased, key, "entropy.thunk.addsub.direct.real");
      llvm::Value* indirect_biased =
          builder.CreateAdd(indirect, key, "entropy.thunk.addsub.indirect.biased");
      llvm::Value* indirect_real =
          builder.CreateSub(indirect_biased, key, "entropy.thunk.addsub.indirect.real");
      llvm::Value* result = llvm::UndefValue::get(pair->getType());
      result =
          builder.CreateInsertValue(result, direct_real, {0}, "entropy.thunk.addsub.insert.direct");
      result = builder.CreateInsertValue(
          result, indirect_real, {1}, "entropy.thunk.addsub.insert.indirect");
      builder.CreateRet(result);
      break;
    }
    case entropy_thunk_shape::select_neutral: {
      llvm::Value* direct = builder.CreateExtractValue(pair, {0}, "entropy.thunk.select.direct");
      llvm::Value* indirect =
          builder.CreateExtractValue(pair, {1}, "entropy.thunk.select.indirect");
      llvm::Value* frozen_direct = builder.CreateFreeze(direct, "entropy.thunk.select.freeze");
      llvm::Value* condition =
          builder.CreateICmpEQ(frozen_direct, frozen_direct, "entropy.thunk.select.cond");
      llvm::Value* neutral = build_entropy_thunk_xor_neutral(
          builder, owner, context, salt, pair, "entropy.thunk.select.neutral");
      llvm::Value* neutral_direct =
          builder.CreateExtractValue(neutral, {0}, "entropy.thunk.select.neutral.direct");
      llvm::Value* neutral_indirect =
          builder.CreateExtractValue(neutral, {1}, "entropy.thunk.select.neutral.indirect");
      llvm::Value* selected_direct = builder.CreateSelect(
          condition, direct, neutral_direct, "entropy.thunk.select.direct.real");
      llvm::Value* selected_indirect = builder.CreateSelect(
          condition, indirect, neutral_indirect, "entropy.thunk.select.indirect.real");
      llvm::Value* result = llvm::UndefValue::get(pair->getType());
      result = builder.CreateInsertValue(
          result, selected_direct, {0}, "entropy.thunk.select.insert.direct");
      result = builder.CreateInsertValue(
          result, selected_indirect, {1}, "entropy.thunk.select.insert.indirect");
      builder.CreateRet(result);
      break;
    }
  }

  return thunk;
}

llvm::Function* get_or_create_entropy_pair_accessor_variant(llvm::Module& module,
                                                            entropy_accessor_variant variant) {
  auto* pair_type = llvm::StructType::get(
      module.getContext(),
      {llvm::Type::getInt64Ty(module.getContext()), llvm::Type::getInt64Ty(module.getContext())});
  const llvm::StringRef accessor_name = get_entropy_accessor_name(variant);
  if (llvm::Function* existing = module.getFunction(accessor_name)) {
    if (existing->getReturnType() != pair_type || !existing->arg_empty()) {
      const std::string message = accessor_name.str() + " has unexpected signature";
      llvm::report_fatal_error(llvm::StringRef(message));
    }
    return existing;
  }

  auto* function_type = llvm::FunctionType::get(pair_type, /*isVarArg=*/false);
  auto* function = llvm::Function::Create(
      function_type, llvm::GlobalValue::ExternalLinkage, accessor_name, module);
  function->setDoesNotThrow();
  return function;
}

llvm::AllocaInst* get_or_create_function_entropy_pair_cache(llvm::Function& function,
                                                            llvm::Function& accessor,
                                                            const builder_context& context,
                                                            std::uint64_t salt) {
  auto* pair_type = llvm::dyn_cast<llvm::StructType>(accessor.getReturnType());
  if (pair_type == nullptr) {
    const std::string message =
        std::string(OBF_RT_LOAD_ENTROPY_PAIR_STR) + " return type is not a struct";
    llvm::report_fatal_error(llvm::StringRef(message));
  }

  llvm::BasicBlock& entry_block = function.getEntryBlock();
  for (llvm::Instruction& instruction : entry_block) {
    auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (alloca == nullptr) { break; }

    if (alloca->getName() == "obf.entropy.cache" && alloca->getAllocatedType() == pair_type) {
      return alloca;
    }
  }

  auto insert_it = entry_block.begin();
  while (insert_it != entry_block.end() && llvm::isa<llvm::AllocaInst>(*insert_it)) { ++insert_it; }

  llvm::IRBuilder<> entry_builder(&entry_block, insert_it);
  auto* cache = entry_builder.CreateAlloca(pair_type, nullptr, "obf.entropy.cache");
  const llvm::DataLayout& data_layout = function.getParent()->getDataLayout();
  cache->setAlignment(data_layout.getPrefTypeAlign(pair_type));
  llvm::Function* thunk =
      get_or_create_entropy_thunk(*function.getParent(), function, accessor, context, salt);
  llvm::Function* initializer = thunk != nullptr ? thunk : &accessor;
  llvm::Value* pair = entry_builder.CreateCall(
      initializer->getFunctionType(), initializer, {}, "obf.entropy.cache.init");
  auto* store = entry_builder.CreateStore(pair, cache);
  store->setAlignment(cache->getAlign());
  return cache;
}

entropy_pair load_entropy_anchor_pair(llvm::IRBuilder<>& builder,
                                      llvm::GlobalVariable* entropy_anchor,
                                      const builder_context& context,
                                      std::uint64_t salt,
                                      llvm::StringRef name) {
  llvm::BasicBlock* block = builder.GetInsertBlock();
  llvm::Function* function = block != nullptr ? block->getParent() : nullptr;
  llvm::Module* module = entropy_anchor->getParent();
  if (module == nullptr || function == nullptr) { return {}; }

  const entropy_accessor_variant accessor_variant =
      select_entropy_accessor_variant(*function, context, salt);
  llvm::Function* accessor = get_or_create_entropy_pair_accessor_variant(*module, accessor_variant);
  llvm::AllocaInst* cache =
      get_or_create_function_entropy_pair_cache(*function, *accessor, context, salt);
  llvm::Value* pair = builder.CreateLoad(accessor->getReturnType(), cache, (name + ".pair").str());
  llvm::cast<llvm::LoadInst>(pair)->setAlignment(cache->getAlign());
  llvm::Value* direct = builder.CreateExtractValue(pair, {0}, (name + ".direct").str());
  llvm::Value* indirect = builder.CreateExtractValue(pair, {1}, (name + ".indirect").str());
  return {.direct = direct, .indirect = indirect};
}

llvm::Value* entangle_value_impl(llvm::IRBuilder<>& builder,
                                 llvm::Value* value,
                                 const builder_context& context,
                                 std::uint64_t salt,
                                 llvm::StringRef name);

llvm::Value* build_opaque_zero_xor_pair(llvm::IRBuilder<>& builder,
                                        llvm::Value* entropy_a,
                                        llvm::Value* entropy_b,
                                        llvm::Constant* mask) {
  llvm::Value* delta = builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.xor_pair.delta");
  llvm::Value* stable_delta = builder.CreateFreeze(delta, "obf.mba.zero.xor_pair.delta.stable");
  llvm::Value* lhs = builder.CreateXor(delta, mask, "obf.mba.zero.xor_pair.lhs");
  llvm::Value* rhs = builder.CreateXor(stable_delta, mask, "obf.mba.zero.xor_pair.rhs");
  return builder.CreateXor(lhs, rhs, "obf.mba.zero.xor_pair");
}

llvm::Value* build_opaque_zero_sub_pair(llvm::IRBuilder<>& builder,
                                        llvm::Value* entropy_a,
                                        llvm::Value* entropy_b,
                                        llvm::Constant* mask) {
  llvm::Value* delta = builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.sub_pair.delta");
  llvm::Value* stable_delta = builder.CreateFreeze(delta, "obf.mba.zero.sub_pair.delta.stable");
  llvm::Value* masked = builder.CreateXor(delta, mask, "obf.mba.zero.sub_pair.masked");
  llvm::Value* unmasked = builder.CreateXor(masked, mask, "obf.mba.zero.sub_pair.unmasked");
  return builder.CreateSub(unmasked, stable_delta, "obf.mba.zero.sub_pair");
}

llvm::Value* build_opaque_zero_affine_cancel_pair(llvm::IRBuilder<>& builder,
                                                  llvm::Value* entropy_a,
                                                  llvm::Value* entropy_b,
                                                  llvm::Type* target_type,
                                                  std::uint64_t salt) {
  if (!is_affine_scalar_type(target_type)) {
    return build_opaque_zero_xor_pair(
        builder, entropy_a, entropy_b, constant_i64_to_type(target_type, salt));
  }

  const unsigned bit_width = target_type->getIntegerBitWidth();
  const llvm::APInt multiplier = make_odd_affine_multiplier(bit_width, salt ^ 0x410a11ceULL);
  const llvm::APInt delta = make_affine_bias(bit_width, salt ^ 0x510a11ceULL);
  llvm::Value* term =
      builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.affine_cancel_pair.term");
  llvm::Value* shifted = builder.CreateAdd(
      term, constant_apint_to_type(target_type, delta), "obf.mba.zero.affine_cancel_pair.shifted");
  llvm::Value* lhs = builder.CreateMul(shifted,
                                       constant_apint_to_type(target_type, multiplier),
                                       "obf.mba.zero.affine_cancel_pair.lhs");
  llvm::Value* scaled_term = builder.CreateMul(term,
                                               constant_apint_to_type(target_type, multiplier),
                                               "obf.mba.zero.affine_cancel_pair.scaled.term");
  llvm::Value* scaled_delta = builder.CreateMul(constant_apint_to_type(target_type, delta),
                                                constant_apint_to_type(target_type, multiplier),
                                                "obf.mba.zero.affine_cancel_pair.scaled.delta");
  llvm::Value* rhs =
      builder.CreateAdd(scaled_term, scaled_delta, "obf.mba.zero.affine_cancel_pair.rhs");
  return builder.CreateSub(lhs, rhs, "obf.mba.zero.affine_cancel_pair");
}

llvm::Value* build_opaque_zero_affine_self_diff(llvm::IRBuilder<>& builder,
                                                llvm::Value* entropy_a,
                                                llvm::Value* entropy_b,
                                                llvm::Type* target_type,
                                                std::uint64_t salt) {
  if (!is_affine_scalar_type(target_type)) {
    return build_opaque_zero_sub_pair(
        builder, entropy_a, entropy_b, constant_i64_to_type(target_type, salt ^ 0x2200ULL));
  }

  const unsigned bit_width = target_type->getIntegerBitWidth();
  const llvm::APInt multiplier = make_odd_affine_multiplier(bit_width, salt ^ 0x610a11ceULL);
  const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
  const llvm::APInt bias = make_affine_bias(bit_width, salt ^ 0x710a11ceULL);
  llvm::Value* term = builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.affine_self_diff.term");
  llvm::Value* encoded =
      build_affine_encode(builder, term, multiplier, bias, "obf.mba.zero.affine_self_diff");
  llvm::Value* decoded =
      build_affine_decode(builder, encoded, inverse, bias, "obf.mba.zero.affine_self_diff");
  return builder.CreateSub(decoded, term, "obf.mba.zero.affine_self_diff.zero");
}

llvm::Value* build_opaque_zero_polynomial_binomial_pair(llvm::IRBuilder<>& builder,
                                                        llvm::Value* entropy_a,
                                                        llvm::Value* entropy_b,
                                                        llvm::Type* target_type,
                                                        const builder_context& context,
                                                        std::uint64_t salt) {
  if (!is_affine_scalar_type(target_type)) {
    return build_opaque_zero_affine_self_diff(builder, entropy_a, entropy_b, target_type, salt);
  }

  const unsigned bit_width = target_type->getIntegerBitWidth();
  llvm::Value* term = builder.CreateFreeze(
      builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.poly_binomial.term.raw"),
      "obf.mba.zero.poly_binomial.term");
  const llvm::APInt c1(bit_width,
                       derive_shape_seed(context, "mba.zero.poly_binomial.c1", salt, target_type),
                       /*isSigned=*/false,
                       /*implicitTrunc=*/true);
  const llvm::APInt c2(bit_width,
                       derive_shape_seed(context, "mba.zero.poly_binomial.c2", salt, target_type),
                       /*isSigned=*/false,
                       /*implicitTrunc=*/true);
  const llvm::APInt csum = c1 + c2;
  const llvm::APInt cprod = c1 * c2;
  llvm::Value* lhs_a = builder.CreateAdd(
      term, constant_apint_to_type(target_type, c1), "obf.mba.zero.poly_binomial.lhs.a");
  llvm::Value* lhs_b = builder.CreateAdd(
      term, constant_apint_to_type(target_type, c2), "obf.mba.zero.poly_binomial.lhs.b");
  llvm::Value* lhs = builder.CreateMul(lhs_a, lhs_b, "obf.mba.zero.poly_binomial.lhs");
  llvm::Value* term_sq = builder.CreateMul(term, term, "obf.mba.zero.poly_binomial.term_sq");
  llvm::Value* linear = builder.CreateMul(
      constant_apint_to_type(target_type, csum), term, "obf.mba.zero.poly_binomial.linear");
  llvm::Value* rhs_partial =
      builder.CreateAdd(term_sq, linear, "obf.mba.zero.poly_binomial.rhs.partial");
  llvm::Value* rhs = builder.CreateAdd(
      rhs_partial, constant_apint_to_type(target_type, cprod), "obf.mba.zero.poly_binomial.rhs");
  return builder.CreateSub(lhs, rhs, "obf.mba.zero.poly_binomial");
}

llvm::Value* build_opaque_zero_polynomial_affine_pair(llvm::IRBuilder<>& builder,
                                                      llvm::Value* entropy_a,
                                                      llvm::Value* entropy_b,
                                                      llvm::Type* target_type,
                                                      const builder_context& context,
                                                      std::uint64_t salt) {
  if (!is_affine_scalar_type(target_type)) {
    return build_opaque_zero_affine_cancel_pair(builder, entropy_a, entropy_b, target_type, salt);
  }

  const unsigned bit_width = target_type->getIntegerBitWidth();
  llvm::Value* term = builder.CreateFreeze(
      builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.poly_affine.term.raw"),
      "obf.mba.zero.poly_affine.term");
  const llvm::APInt coeff_a = make_odd_affine_multiplier(
      bit_width, derive_shape_seed(context, "mba.zero.poly_affine.coeff_a", salt, target_type));
  const llvm::APInt coeff_b = make_affine_bias(
      bit_width, derive_shape_seed(context, "mba.zero.poly_affine.coeff_b", salt, target_type));
  const llvm::APInt multiplier = make_odd_affine_multiplier(
      bit_width, derive_shape_seed(context, "mba.zero.poly_affine.multiplier", salt, target_type));
  const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
  const llvm::APInt bias = make_affine_bias(
      bit_width, derive_shape_seed(context, "mba.zero.poly_affine.bias", salt, target_type));

  llvm::Value* term_sq = builder.CreateMul(term, term, "obf.mba.zero.poly_affine.term_sq");
  llvm::Value* poly_scaled = builder.CreateMul(constant_apint_to_type(target_type, coeff_a),
                                               term_sq,
                                               "obf.mba.zero.poly_affine.poly_scaled");
  llvm::Value* poly = builder.CreateAdd(
      poly_scaled, constant_apint_to_type(target_type, coeff_b), "obf.mba.zero.poly_affine.poly");
  llvm::Value* lhs_encoded =
      build_affine_encode(builder, poly, multiplier, bias, "obf.mba.zero.poly_affine.lhs");
  llvm::Value* rhs_encoded =
      build_affine_encode(builder, poly, multiplier, bias, "obf.mba.zero.poly_affine.rhs");
  llvm::Value* lhs =
      build_affine_decode(builder, lhs_encoded, inverse, bias, "obf.mba.zero.poly_affine.lhs.dec");
  llvm::Value* rhs =
      build_affine_decode(builder, rhs_encoded, inverse, bias, "obf.mba.zero.poly_affine.rhs.dec");
  return builder.CreateSub(lhs, rhs, "obf.mba.zero.poly_affine");
}

llvm::Value* build_opaque_zero_for_shape(llvm::IRBuilder<>& builder,
                                         opaque_zero_shape shape,
                                         llvm::Value* entropy_a,
                                         llvm::Value* entropy_b,
                                         llvm::Type* target_type,
                                         const builder_context& context,
                                         llvm::Constant* mask,
                                         std::uint64_t salt) {
  // Every family must reduce to semantic zero on its own. That keeps opaque
  // predicates and constant masks correct even if future entropy accessors stop
  // returning identical pair components.
  switch (shape) {
    case opaque_zero_shape::xor_pair:
      return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
    case opaque_zero_shape::add_sub_pair: {
      llvm::Value* delta =
          builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.add_sub_pair.delta");
      llvm::Value* stable_delta =
          builder.CreateFreeze(delta, "obf.mba.zero.add_sub_pair.delta.stable");
      llvm::Value* lhs = builder.CreateAdd(delta, mask, "obf.mba.zero.add_sub_pair.lhs");
      llvm::Value* rhs = builder.CreateAdd(stable_delta, mask, "obf.mba.zero.add_sub_pair.rhs");
      return builder.CreateSub(lhs, rhs, "obf.mba.zero.add_sub_pair");
    }
    case opaque_zero_shape::sub_pair:
      return build_opaque_zero_sub_pair(builder, entropy_a, entropy_b, mask);
    case opaque_zero_shape::rotate_xor_pair: {
      if (!target_type->isIntegerTy()) {
        return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
      }

      llvm::Value* delta =
          builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.rotate_xor_pair.delta");
      llvm::Value* stable_delta =
          builder.CreateFreeze(delta, "obf.mba.zero.rotate_xor_pair.delta.stable");
      llvm::Value* lhs_seed =
          builder.CreateXor(delta, mask, "obf.mba.zero.rotate_xor_pair.lhs.seed");
      llvm::Value* rhs_seed =
          builder.CreateXor(stable_delta, mask, "obf.mba.zero.rotate_xor_pair.rhs.seed");
      const unsigned bit_width = target_type->getIntegerBitWidth();
      if (bit_width <= 1) {
        return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
      }

      const unsigned amount = static_cast<unsigned>((salt % (bit_width - 1)) + 1);
      llvm::Value* lhs =
          rotate_left_scalar(builder, lhs_seed, amount, "obf.mba.zero.rotate_xor_pair.lhs");
      llvm::Value* rhs =
          rotate_left_scalar(builder, rhs_seed, amount, "obf.mba.zero.rotate_xor_pair.rhs");
      if (lhs == nullptr || rhs == nullptr) {
        return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
      }
      return builder.CreateXor(lhs, rhs, "obf.mba.zero.rotate_xor_pair");
    }
    case opaque_zero_shape::cmp_select_pair: {
      llvm::Value* equal =
          builder.CreateICmpEQ(entropy_a, entropy_b, "obf.mba.zero.cmp_select_pair.eq");
      llvm::Value* delta =
          builder.CreateXor(entropy_a, entropy_b, "obf.mba.zero.cmp_select_pair.delta");
      llvm::Value* stable_delta =
          builder.CreateFreeze(delta, "obf.mba.zero.cmp_select_pair.delta.stable");
      llvm::Value* zero_alt =
          builder.CreateSub(delta, stable_delta, "obf.mba.zero.cmp_select_pair.zero.alt");
      return builder.CreateSelect(equal,
                                  llvm::Constant::getNullValue(target_type),
                                  zero_alt,
                                  "obf.mba.zero.cmp_select_pair");
    }
    case opaque_zero_shape::affine_cancel_pair:
      return build_opaque_zero_affine_cancel_pair(builder, entropy_a, entropy_b, target_type, salt);
    case opaque_zero_shape::affine_self_diff:
      return build_opaque_zero_affine_self_diff(builder, entropy_a, entropy_b, target_type, salt);
    case opaque_zero_shape::linear_equiv_pair: {
      if (!supports_shift_by_one(target_type)) {
        return build_opaque_zero_sub_pair(
            builder, entropy_a, entropy_b, constant_i64_to_type(target_type, salt ^ 0x3300ULL));
      }

      // (x | y) + (x & y) and (x ^ y) + ((x & y) << 1) are both x + y.
      llvm::Value* stable_a = builder.CreateFreeze(entropy_a, "obf.mba.zero.linear_equiv_pair.a");
      llvm::Value* stable_b = builder.CreateFreeze(entropy_b, "obf.mba.zero.linear_equiv_pair.b");
      llvm::Value* or_part =
          builder.CreateOr(stable_a, stable_b, "obf.mba.zero.linear_equiv_pair.or");
      llvm::Value* and_part =
          builder.CreateAnd(stable_a, stable_b, "obf.mba.zero.linear_equiv_pair.and");
      llvm::Value* lhs = builder.CreateAdd(or_part, and_part, "obf.mba.zero.linear_equiv_pair.lhs");
      llvm::Value* xor_part =
          builder.CreateXor(stable_a, stable_b, "obf.mba.zero.linear_equiv_pair.xor");
      llvm::Constant* one = constant_i64_to_type(target_type, 1);
      llvm::Value* carry = builder.CreateShl(and_part, one, "obf.mba.zero.linear_equiv_pair.carry");
      llvm::Value* rhs = builder.CreateAdd(xor_part, carry, "obf.mba.zero.linear_equiv_pair.rhs");
      return builder.CreateSub(lhs, rhs, "obf.mba.zero.linear_equiv_pair");
    }
    case opaque_zero_shape::polynomial_binomial_pair:
      return build_opaque_zero_polynomial_binomial_pair(
          builder, entropy_a, entropy_b, target_type, context, salt);
    case opaque_zero_shape::polynomial_affine_pair:
      return build_opaque_zero_polynomial_affine_pair(
          builder, entropy_a, entropy_b, target_type, context, salt);
  }

  return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
}

llvm::Value* build_opaque_zero(llvm::IRBuilder<>& builder,
                               const builder_context& context,
                               llvm::Type* target_type,
                               std::uint64_t salt) {
  if (context.entropy_anchor == nullptr || !is_supported_type(target_type)) {
    return llvm::Constant::getNullValue(target_type);
  }

  const entropy_pair entropy =
      load_entropy_anchor_pair(builder, context.entropy_anchor, context, salt, "obf.entropy");
  if (entropy.direct == nullptr || entropy.indirect == nullptr) {
    return llvm::Constant::getNullValue(target_type);
  }

  llvm::Value* entropy_a =
      cast_i64_to_type(builder, entropy.direct, target_type, "obf.entropy.a.cast");
  llvm::Value* entropy_b =
      cast_i64_to_type(builder, entropy.indirect, target_type, "obf.entropy.b.cast");
  llvm::Constant* mask =
      constant_i64_to_type(target_type, mix_seed(context.seed_base, salt ^ 0x13579bdfULL));
  return build_opaque_zero_for_shape(builder,
                                     select_opaque_zero_shape(context, salt),
                                     entropy_a,
                                     entropy_b,
                                     target_type,
                                     context,
                                     mask,
                                     salt);
}

llvm::Value* entangle_value_impl(llvm::IRBuilder<>& builder,
                                 llvm::Value* value,
                                 const builder_context& context,
                                 std::uint64_t salt,
                                 llvm::StringRef name) {
  if (context.entropy_anchor == nullptr || !is_supported_type(value->getType())) { return value; }

  llvm::Type* type = value->getType();
  llvm::Value* zero = build_opaque_zero(builder, context, type, salt);
  const llvm::Twine result_name = name.empty() ? "obf.entropy.value" : name;

  switch (select_entangle_shape(context, salt)) {
    case entangle_shape::xor_zero: {
      llvm::Value* shape_zero =
          builder.CreateXor(zero, llvm::Constant::getNullValue(type), "obf.entangle.xor_zero.zero");
      return builder.CreateXor(value, shape_zero, result_name);
    }
    case entangle_shape::add_zero: {
      llvm::Value* shape_zero =
          builder.CreateAdd(zero, llvm::Constant::getNullValue(type), "obf.entangle.add_zero.zero");
      return builder.CreateAdd(value, shape_zero, result_name);
    }
    case entangle_shape::sub_zero: {
      llvm::Value* shape_zero =
          builder.CreateAdd(zero, llvm::Constant::getNullValue(type), "obf.entangle.sub_zero.zero");
      return builder.CreateSub(value, shape_zero, result_name);
    }
    case entangle_shape::xor_masked_pair: {
      llvm::Constant* mask =
          constant_i64_to_type(type, mix_seed(context.seed_base, salt ^ 0x78dde6a3ULL));
      llvm::Value* masked = builder.CreateXor(value, mask, "obf.entangle.xor_masked_pair.masked");
      llvm::Value* unmasked =
          builder.CreateXor(masked, mask, "obf.entangle.xor_masked_pair.unmasked");
      return builder.CreateXor(unmasked, zero, result_name);
    }
    case entangle_shape::add_sub_masked_pair: {
      llvm::Constant* mask =
          constant_i64_to_type(type, mix_seed(context.seed_base, salt ^ 0x412ad0f5ULL));
      llvm::Value* masked = builder.CreateAdd(value, mask, "obf.entangle.add_sub_masked_pair.add");
      llvm::Value* unmasked =
          builder.CreateSub(masked, mask, "obf.entangle.add_sub_masked_pair.sub");
      return builder.CreateAdd(unmasked, zero, result_name);
    }
  }

  return builder.CreateXor(value, zero, result_name);
}

llvm::Value* mask_with_zero_add(llvm::IRBuilder<>& builder,
                                llvm::Value* value,
                                const builder_context& context,
                                std::uint64_t salt,
                                llvm::StringRef name) {
  return builder.CreateAdd(
      value, build_opaque_zero(builder, context, value->getType(), salt), name);
}

llvm::Value* mask_with_zero_xor(llvm::IRBuilder<>& builder,
                                llvm::Value* value,
                                const builder_context& context,
                                std::uint64_t salt,
                                llvm::StringRef name) {
  return builder.CreateXor(
      value, build_opaque_zero(builder, context, value->getType(), salt), name);
}

llvm::Value* create_add_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value* create_sub_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value* create_mul_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name) {
  const std::string result_name = name.empty() ? "obf.mba.mul" : name.str();
  if (!derive_features(context).enable_multiplication || !lhs->getType()->isIntegerTy() ||
      lhs->getType() != rhs->getType()) {
    return entangle_value_impl(
        builder, builder.CreateMul(lhs, rhs, result_name), context, salt, result_name);
  }

  llvm::Value* variable = lhs;
  const llvm::ConstantInt* constant_operand = llvm::dyn_cast<llvm::ConstantInt>(rhs);
  if (constant_operand == nullptr) {
    constant_operand = llvm::dyn_cast<llvm::ConstantInt>(lhs);
    variable = rhs;
  }

  if (constant_operand == nullptr) {
    return entangle_value_impl(
        builder, builder.CreateMul(lhs, rhs, result_name), context, salt, result_name);
  }

  const llvm::APInt constant = constant_operand->getValue();
  if (constant.isZero()) {
    return entangle_value_impl(builder,
                               llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(lhs->getType()), constant),
                               context,
                               salt,
                               result_name);
  }
  if (constant == llvm::APInt(constant.getBitWidth(), 1)) {
    return entangle_value_impl(builder, variable, context, salt, result_name);
  }

  const llvm::APInt magnitude = constant.isNegative() ? -constant : constant;
  if (!has_budget(context, 18) || magnitude.popcount() == 0 || magnitude.popcount() > 3) {
    return entangle_value_impl(
        builder, builder.CreateMul(lhs, rhs, result_name), context, salt, result_name);
  }

  llvm::Value* accumulated = nullptr;
  unsigned term_index = 0;
  for (unsigned bit = 0; bit < magnitude.getBitWidth(); ++bit) {
    if (!magnitude[bit]) { continue; }

    llvm::Value* term = variable;
    if (bit != 0) {
      term = builder.CreateShl(variable,
                               constant_i64_to_type(variable->getType(), bit),
                               (result_name + ".term.shl." + llvm::Twine(term_index)).str());
    }
    term = mask_with_zero_add(builder,
                              term,
                              context,
                              salt + 0x200ULL + term_index,
                              (result_name + ".term." + llvm::Twine(term_index)).str());
    if (accumulated == nullptr) {
      accumulated = term;
    } else {
      accumulated = create_add_impl(builder,
                                    accumulated,
                                    term,
                                    context,
                                    mix_seed(salt, 0x401ULL + term_index),
                                    (result_name + ".acc." + llvm::Twine(term_index)).str(),
                                    clamped_depth(context) > 0 ? clamped_depth(context) - 1 : 0);
    }
    ++term_index;
  }

  if (accumulated == nullptr) {
    accumulated = llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(lhs->getType()), 0);
  }
  if (constant.isNegative()) {
    accumulated = create_sub_impl(builder,
                                  llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(lhs->getType()), 0),
                                  accumulated,
                                  context,
                                  mix_seed(salt, 0x577ULL),
                                  result_name + ".neg",
                                  clamped_depth(context) > 0 ? clamped_depth(context) - 1 : 0);
  }

  return entangle_value_impl(builder, accumulated, context, salt + 0x2ffULL, result_name);
}

llvm::Value* create_udiv_impl(llvm::IRBuilder<>& builder,
                              llvm::Value* lhs,
                              llvm::Value* rhs,
                              const builder_context& context,
                              std::uint64_t salt,
                              llvm::StringRef name) {
  const mba_features features = derive_features(context);
  if (!features.enable_division_constants || !lhs->getType()->isIntegerTy() ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateUDiv(lhs, rhs, name.empty() ? "obf.mba.udiv" : name);
  }

  const auto* divisor = llvm::dyn_cast<llvm::ConstantInt>(rhs);
  if (divisor == nullptr || divisor->isZero() || !divisor->getValue().isPowerOf2()) {
    return builder.CreateUDiv(lhs, rhs, name.empty() ? "obf.mba.udiv" : name);
  }

  const unsigned shift_amount = divisor->getValue().logBase2();
  llvm::Value* masked_lhs = mask_with_zero_xor(
      builder, lhs, context, salt + 0x611ULL, (name.empty() ? "obf.mba.udiv" : name).str() + ".lhs");
  return builder.CreateLShr(masked_lhs,
                            constant_i64_to_type(lhs->getType(), shift_amount),
                            name.empty() ? "obf.mba.udiv" : name);
}

llvm::Value* create_urem_impl(llvm::IRBuilder<>& builder,
                              llvm::Value* lhs,
                              llvm::Value* rhs,
                              const builder_context& context,
                              std::uint64_t salt,
                              llvm::StringRef name) {
  const mba_features features = derive_features(context);
  if (!features.enable_division_constants || !lhs->getType()->isIntegerTy() ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateURem(lhs, rhs, name.empty() ? "obf.mba.urem" : name);
  }

  const auto* divisor = llvm::dyn_cast<llvm::ConstantInt>(rhs);
  if (divisor == nullptr || divisor->isZero() || !divisor->getValue().isPowerOf2()) {
    return builder.CreateURem(lhs, rhs, name.empty() ? "obf.mba.urem" : name);
  }

  llvm::APInt remainder_mask = divisor->getValue() - 1;
  llvm::Value* masked_lhs = mask_with_zero_add(
      builder, lhs, context, salt + 0x711ULL, (name.empty() ? "obf.mba.urem" : name).str() + ".lhs");
  return builder.CreateAnd(masked_lhs,
                           constant_apint_to_type(lhs->getType(), remainder_mask),
                           name.empty() ? "obf.mba.urem" : name);
}

// ---------------------------------------------------------------------------
// Recursive MBA implementation helpers.
//
// Each *_impl function takes an explicit remaining_depth counter.
//   remaining_depth == 0  →  emit the plain LLVM binary operation (base case).
//   remaining_depth >= 1  →  one layer of MBA expansion; the combining
//                            binary op at the bottom recurses with depth − 1.
//
// The public create_{add,sub,xor} functions delegate here using
// min(context.depth, max_mba_depth) so callers never have to think about
// capping.
// ---------------------------------------------------------------------------

llvm::Value* create_add_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value* create_sub_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value* create_xor_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value* create_add_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateAdd(lhs, rhs, name.empty() ? "obf.mba.add" : name);
  }

  switch (select_add_shape(context, salt)) {
    case add_shape::or_and: {
      llvm::Value* or_part = builder.CreateOr(lhs, rhs, "obf.mba.add.or");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.and");
      llvm::Value* lhs_term =
          mask_with_zero_add(builder, or_part, context, salt + 0x11, "obf.mba.add.left");
      llvm::Value* rhs_term =
          mask_with_zero_xor(builder, and_part, context, salt + 0x29, "obf.mba.add.right");
      return create_add_impl(builder,
                             lhs_term,
                             rhs_term,
                             context,
                             mix_seed(salt, 0xd1ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case add_shape::xor_carry: {
      llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.add.xor");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.and");
      llvm::Value* carry = builder.CreateAdd(
          and_part,
          mask_with_zero_xor(builder, and_part, context, salt + 0x3d, "obf.mba.add.carry.mask"),
          "obf.mba.add.carry");
      llvm::Value* masked_xor =
          mask_with_zero_add(builder, xor_part, context, salt + 0x47, "obf.mba.add.xor.mask");
      return create_add_impl(builder,
                             masked_xor,
                             carry,
                             context,
                             mix_seed(salt, 0xd2ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case add_shape::affine_xor_carry: {
      if (!is_affine_scalar_type(lhs->getType())) {
        return create_add_impl(builder,
                               lhs,
                               rhs,
                               context,
                               mix_seed(salt, 0xd3ULL * remaining_depth),
                               name,
                               remaining_depth - 1);
      }

      const unsigned bit_width = lhs->getType()->getIntegerBitWidth();
      const llvm::APInt multiplier =
          make_odd_affine_multiplier(bit_width, mix_seed(context.seed_base, salt ^ 0xa110ULL));
      const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
      const llvm::APInt bias =
          make_affine_bias(bit_width, mix_seed(context.seed_base, salt ^ 0xa111ULL));
      llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.add.affine.xor");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.affine.and");
      llvm::Value* carry_base = builder.CreateShl(
          and_part,
          llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(lhs->getType()), 1),
          "obf.mba.add.affine.carry.base");
      llvm::Value* carry =
          mask_with_zero_add(builder, carry_base, context, salt + 0x4d, "obf.mba.add.affine.carry");
      llvm::Value* enc_xor =
          build_affine_encode(builder, xor_part, multiplier, bias, "obf.mba.add.affine.xor");
      llvm::Value* enc_carry =
          build_affine_encode(builder, carry, multiplier, bias, "obf.mba.add.affine.carry");
      llvm::Value* encoded_sum =
          builder.CreateSub(builder.CreateAdd(enc_xor, enc_carry, "obf.mba.add.affine.enc.sum"),
                            constant_apint_to_type(lhs->getType(), bias),
                            "obf.mba.add.affine.enc.norm");
      llvm::Value* decoded =
          build_affine_decode(builder, encoded_sum, inverse, bias, "obf.mba.add.affine.sum");
      llvm::Value* masked =
          mask_with_zero_xor(builder, decoded, context, salt + 0x57, "obf.mba.add.affine.mask");
      return create_add_impl(builder,
                             masked,
                             build_opaque_zero(builder, context, lhs->getType(), salt + 0x59),
                             context,
                             mix_seed(salt, 0xd4ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case add_shape::xor_shifted_carry: {
      if (!supports_shift_by_one(lhs->getType())) {
        return create_add_impl(builder,
                               lhs,
                               rhs,
                               context,
                               mix_seed(salt, 0xd5ULL * remaining_depth),
                               name,
                               remaining_depth - 1);
      }

      // x + y == (x ^ y) + ((x & y) << 1) in modular integer arithmetic.
      llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.add.xor_shifted_carry.xor");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.xor_shifted_carry.and");
      llvm::Value* carry_base = builder.CreateShl(and_part,
                                                  constant_i64_to_type(lhs->getType(), 1),
                                                  "obf.mba.add.xor_shifted_carry.carry.base");
      llvm::Value* masked_xor = mask_with_zero_xor(
          builder, xor_part, context, salt + 0x5b, "obf.mba.add.xor_shifted_carry.xor.mask");
      llvm::Value* carry = mask_with_zero_add(
          builder, carry_base, context, salt + 0x5d, "obf.mba.add.xor_shifted_carry.carry");
      return create_add_impl(builder,
                             masked_xor,
                             carry,
                             context,
                             mix_seed(salt, 0xd6ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
  }

  llvm_unreachable("unknown add MBA shape");
}

llvm::Value* create_sub_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateSub(lhs, rhs, name.empty() ? "obf.mba.sub" : name);
  }

  switch (select_sub_shape(context, salt)) {
    case sub_shape::xor_borrow: {
      llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.sub.xor");
      llvm::Value* borrow_mask = builder.CreateAnd(
          builder.CreateNot(lhs, "obf.mba.sub.notlhs"), rhs, "obf.mba.sub.borrow.mask");
      llvm::Value* borrow = builder.CreateAdd(
          borrow_mask,
          mask_with_zero_xor(
              builder, borrow_mask, context, salt + 0x53, "obf.mba.sub.borrow.masked"),
          "obf.mba.sub.borrow");
      llvm::Value* masked_xor =
          mask_with_zero_add(builder, xor_part, context, salt + 0x61, "obf.mba.sub.xor.mask");
      return create_sub_impl(builder,
                             masked_xor,
                             borrow,
                             context,
                             mix_seed(salt, 0xe1ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case sub_shape::lhs_rhs_only: {
      llvm::Value* lhs_only = builder.CreateAnd(
          lhs, builder.CreateNot(rhs, "obf.mba.sub.notrhs"), "obf.mba.sub.lhs.only");
      llvm::Value* rhs_only = builder.CreateAnd(
          builder.CreateNot(lhs, "obf.mba.sub.notlhs2"), rhs, "obf.mba.sub.rhs.only");
      llvm::Value* masked_lhs =
          mask_with_zero_xor(builder, lhs_only, context, salt + 0x73, "obf.mba.sub.left");
      llvm::Value* masked_rhs =
          mask_with_zero_add(builder, rhs_only, context, salt + 0x79, "obf.mba.sub.right");
      return create_sub_impl(builder,
                             masked_lhs,
                             masked_rhs,
                             context,
                             mix_seed(salt, 0xe2ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case sub_shape::affine_xor_borrow: {
      if (!is_affine_scalar_type(lhs->getType())) {
        return create_sub_impl(builder,
                               lhs,
                               rhs,
                               context,
                               mix_seed(salt, 0xe3ULL * remaining_depth),
                               name,
                               remaining_depth - 1);
      }

      const unsigned bit_width = lhs->getType()->getIntegerBitWidth();
      const llvm::APInt multiplier =
          make_odd_affine_multiplier(bit_width, mix_seed(context.seed_base, salt ^ 0xb110ULL));
      const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
      const llvm::APInt bias =
          make_affine_bias(bit_width, mix_seed(context.seed_base, salt ^ 0xb111ULL));
      llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.sub.affine.xor");
      llvm::Value* borrow_mask =
          builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.sub.affine.notlhs"),
                            rhs,
                            "obf.mba.sub.affine.borrow.mask");
      llvm::Value* borrow_base = builder.CreateShl(
          borrow_mask,
          llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(lhs->getType()), 1),
          "obf.mba.sub.affine.borrow.base");
      llvm::Value* borrow = mask_with_zero_add(
          builder, borrow_base, context, salt + 0x7d, "obf.mba.sub.affine.borrow");
      llvm::Value* enc_xor =
          build_affine_encode(builder, xor_part, multiplier, bias, "obf.mba.sub.affine.xor");
      llvm::Value* enc_borrow =
          build_affine_encode(builder, borrow, multiplier, bias, "obf.mba.sub.affine.borrow");
      llvm::Value* encoded_diff =
          builder.CreateAdd(builder.CreateSub(enc_xor, enc_borrow, "obf.mba.sub.affine.enc.diff"),
                            constant_apint_to_type(lhs->getType(), bias),
                            "obf.mba.sub.affine.enc.norm");
      llvm::Value* decoded =
          build_affine_decode(builder, encoded_diff, inverse, bias, "obf.mba.sub.affine.diff");
      llvm::Value* masked =
          mask_with_zero_xor(builder, decoded, context, salt + 0x87, "obf.mba.sub.affine.mask");
      return create_sub_impl(builder,
                             masked,
                             build_opaque_zero(builder, context, lhs->getType(), salt + 0x89),
                             context,
                             mix_seed(salt, 0xe4ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case sub_shape::ones_complement_add: {
      // x - y == x + ~y + 1 modulo 2^n.
      llvm::Value* not_rhs = builder.CreateNot(rhs, "obf.mba.sub.ones_complement.notrhs");
      llvm::Value* masked_lhs =
          mask_with_zero_add(builder, lhs, context, salt + 0x8b, "obf.mba.sub.ones_complement.lhs");
      llvm::Value* masked_not = mask_with_zero_xor(
          builder, not_rhs, context, salt + 0x8d, "obf.mba.sub.ones_complement.notrhs.mask");
      llvm::Value* partial = create_add_impl(builder,
                                             masked_lhs,
                                             masked_not,
                                             context,
                                             mix_seed(salt, 0xe5ULL * remaining_depth),
                                             "obf.mba.sub.ones_complement.partial",
                                             remaining_depth - 1);
      return create_add_impl(builder,
                             partial,
                             constant_i64_to_type(lhs->getType(), 1),
                             context,
                             mix_seed(salt, 0xe6ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
  }

  llvm_unreachable("unknown sub MBA shape");
}

llvm::Value* create_xor_impl(llvm::IRBuilder<>& builder,
                             llvm::Value* lhs,
                             llvm::Value* rhs,
                             const builder_context& context,
                             std::uint64_t salt,
                             llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateXor(lhs, rhs, name.empty() ? "obf.mba.xor" : name);
  }

  switch (select_xor_shape(context, salt)) {
    case xor_shape::or_and_sub: {
      llvm::Value* or_part = builder.CreateOr(lhs, rhs, "obf.mba.xor.or");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.xor.and");
      llvm::Value* masked_or =
          mask_with_zero_add(builder, or_part, context, salt + 0x89, "obf.mba.xor.left");
      llvm::Value* masked_and =
          mask_with_zero_xor(builder, and_part, context, salt + 0x97, "obf.mba.xor.right");
      return create_sub_impl(builder,
                             masked_or,
                             masked_and,
                             context,
                             mix_seed(salt, 0xf1ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case xor_shape::disjoint_sum: {
      llvm::Value* lhs_only = builder.CreateAnd(
          lhs, builder.CreateNot(rhs, "obf.mba.xor.notrhs"), "obf.mba.xor.lhs.only");
      llvm::Value* rhs_only = builder.CreateAnd(
          builder.CreateNot(lhs, "obf.mba.xor.notlhs"), rhs, "obf.mba.xor.rhs.only");
      llvm::Value* masked_lhs =
          mask_with_zero_xor(builder, lhs_only, context, salt + 0xa3, "obf.mba.xor.left.mask");
      llvm::Value* masked_rhs =
          mask_with_zero_add(builder, rhs_only, context, salt + 0xb1, "obf.mba.xor.right.mask");
      return create_add_impl(builder,
                             masked_lhs,
                             masked_rhs,
                             context,
                             mix_seed(salt, 0xf2ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case xor_shape::affine_or_and_sub: {
      if (!is_affine_scalar_type(lhs->getType())) {
        return create_xor_impl(builder,
                               lhs,
                               rhs,
                               context,
                               mix_seed(salt, 0xf3ULL * remaining_depth),
                               name,
                               remaining_depth - 1);
      }

      const unsigned bit_width = lhs->getType()->getIntegerBitWidth();
      const llvm::APInt multiplier =
          make_odd_affine_multiplier(bit_width, mix_seed(context.seed_base, salt ^ 0xc110ULL));
      const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
      const llvm::APInt bias =
          make_affine_bias(bit_width, mix_seed(context.seed_base, salt ^ 0xc111ULL));
      llvm::Value* or_part = builder.CreateOr(lhs, rhs, "obf.mba.xor.affine.or");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.xor.affine.and");
      llvm::Value* enc_or =
          build_affine_encode(builder, or_part, multiplier, bias, "obf.mba.xor.affine.or");
      llvm::Value* enc_and =
          build_affine_encode(builder, and_part, multiplier, bias, "obf.mba.xor.affine.and");
      llvm::Value* encoded =
          builder.CreateAdd(builder.CreateSub(enc_or, enc_and, "obf.mba.xor.affine.enc.diff"),
                            constant_apint_to_type(lhs->getType(), bias),
                            "obf.mba.xor.affine.enc.norm");
      llvm::Value* decoded =
          build_affine_decode(builder, encoded, inverse, bias, "obf.mba.xor.affine.diff");
      llvm::Value* masked =
          mask_with_zero_add(builder, decoded, context, salt + 0xbb, "obf.mba.xor.affine.mask");
      return create_add_impl(builder,
                             masked,
                             build_opaque_zero(builder, context, lhs->getType(), salt + 0xbd),
                             context,
                             mix_seed(salt, 0xf4ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
    case xor_shape::sum_minus_carry: {
      if (!supports_shift_by_one(lhs->getType())) {
        return create_xor_impl(builder,
                               lhs,
                               rhs,
                               context,
                               mix_seed(salt, 0xf5ULL * remaining_depth),
                               name,
                               remaining_depth - 1);
      }

      // x ^ y == (x + y) - ((x & y) << 1) in modular integer arithmetic.
      llvm::Value* sum = builder.CreateAdd(lhs, rhs, "obf.mba.xor.sum_minus_carry.sum");
      llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.mba.xor.sum_minus_carry.and");
      llvm::Value* carry = builder.CreateShl(
          and_part, constant_i64_to_type(lhs->getType(), 1), "obf.mba.xor.sum_minus_carry.carry");
      llvm::Value* masked_sum = mask_with_zero_xor(
          builder, sum, context, salt + 0xc1, "obf.mba.xor.sum_minus_carry.sum.mask");
      llvm::Value* masked_carry = mask_with_zero_add(
          builder, carry, context, salt + 0xc3, "obf.mba.xor.sum_minus_carry.carry.mask");
      return create_sub_impl(builder,
                             masked_sum,
                             masked_carry,
                             context,
                             mix_seed(salt, 0xf6ULL * remaining_depth),
                             name,
                             remaining_depth - 1);
    }
  }

  llvm_unreachable("unknown xor MBA shape");
}

}  // namespace

llvm::GlobalVariable* get_or_create_entropy_anchor(llvm::Module& module) {
  if (llvm::GlobalVariable* existing = module.getNamedGlobal(OBF_RT_ENTROPY_ANCHOR_STR)) {
    return existing;
  }

  auto* anchor = new llvm::GlobalVariable(module,
                                          llvm::Type::getInt64Ty(module.getContext()),
                                          /*isConstant=*/false,
                                          llvm::GlobalValue::ExternalLinkage,
                                          /*Initializer=*/nullptr,
                                          OBF_RT_ENTROPY_ANCHOR_STR);
  anchor->setExternallyInitialized(true);
  anchor->setAlignment(llvm::Align(8));
  return anchor;
}

builder_context get_or_create_builder_context(llvm::Function& function,
                                              llvm::StringRef prefix,
                                              std::uint64_t seed_base) {
  llvm::Module* module = function.getParent();
  return {.entropy_anchor = module == nullptr ? nullptr : get_or_create_entropy_anchor(*module),
          .seed_base = derive_function_seed(function, prefix, seed_base)};
}

llvm::Value* entangle_value(llvm::IRBuilder<>& builder,
                            llvm::Value* value,
                            const builder_context& context,
                            std::uint64_t salt,
                            llvm::StringRef name) {
  return entangle_value_impl(builder, value, context, salt, name);
}

llvm::Value* create_opaque_integer(llvm::IRBuilder<>& builder,
                                   llvm::IntegerType* type,
                                   const builder_context& context,
                                   const llvm::APInt& value,
                                   std::uint64_t salt,
                                   llvm::StringRef name) {
  const llvm::APInt normalized = value.sextOrTrunc(type->getBitWidth());
  const std::string result_name = name.empty() ? "obf.seed" : name.str();
  const auto make_key = [&](std::uint64_t family_salt) {
    llvm::APInt key(type->getBitWidth(),
                    derive_shape_seed(context, "mba.opaque_integer.key", salt ^ family_salt, type),
                    /*isSigned=*/false,
                    /*implicitTrunc=*/true);
    if (key.isZero() && type->getBitWidth() > 1) { key = llvm::APInt(type->getBitWidth(), 0x5aU); }
    return key;
  };

  switch (select_opaque_integer_shape(context, salt, type)) {
    case opaque_integer_shape::entangled_constant:
      return entangle_value_impl(
          builder, llvm::ConstantInt::get(type, normalized), context, salt, result_name);
    case opaque_integer_shape::xor_split: {
      const llvm::APInt key = make_key(0x7811ULL);
      llvm::Value* masked = llvm::ConstantInt::get(type, normalized ^ key);
      llvm::Value* opaque_key = entangle_value_impl(builder,
                                                    llvm::ConstantInt::get(type, key),
                                                    context,
                                                    salt + 0x17ULL,
                                                    "obf.seed.xor_split.key");
      llvm::Value* decoded = builder.CreateXor(masked, opaque_key, "obf.seed.xor_split.value");
      return entangle_value_impl(builder, decoded, context, salt + 0x19ULL, result_name);
    }
    case opaque_integer_shape::add_split: {
      const llvm::APInt key = make_key(0xadd5ULL);
      llvm::Value* biased = llvm::ConstantInt::get(type, normalized - key);
      llvm::Value* opaque_key = entangle_value_impl(builder,
                                                    llvm::ConstantInt::get(type, key),
                                                    context,
                                                    salt + 0x1bULL,
                                                    "obf.seed.add_split.key");
      llvm::Value* decoded = builder.CreateAdd(biased, opaque_key, "obf.seed.add_split.value");
      return entangle_value_impl(builder, decoded, context, salt + 0x1dULL, result_name);
    }
    case opaque_integer_shape::affine_decode: {
      if (type->getBitWidth() <= 1) {
        return entangle_value_impl(
            builder, llvm::ConstantInt::get(type, normalized), context, salt, result_name);
      }

      const llvm::APInt multiplier = make_odd_affine_multiplier(
          type->getBitWidth(), derive_shape_seed(context, "mba.opaque_integer.affine", salt, type));
      const llvm::APInt inverse = compute_mod_inverse_pow2(multiplier);
      const llvm::APInt bias = make_affine_bias(
          type->getBitWidth(), derive_shape_seed(context, "mba.opaque_integer.bias", salt, type));
      const llvm::APInt encoded = normalized * multiplier + bias;
      llvm::Value* opaque_encoded = entangle_value_impl(builder,
                                                        llvm::ConstantInt::get(type, encoded),
                                                        context,
                                                        salt + 0x1fULL,
                                                        "obf.seed.affine.encoded");
      llvm::Value* decoded =
          build_affine_decode(builder, opaque_encoded, inverse, bias, "obf.seed.affine");
      return entangle_value_impl(builder, decoded, context, salt + 0x23ULL, result_name);
    }
    case opaque_integer_shape::zero_add: {
      llvm::Value* zero = build_opaque_zero(builder, context, type, salt + 0x25ULL);
      llvm::Value* decoded = builder.CreateAdd(
          llvm::ConstantInt::get(type, normalized), zero, "obf.seed.zero_add.value");
      return entangle_value_impl(builder, decoded, context, salt + 0x27ULL, result_name);
    }
  }

  llvm_unreachable("unknown opaque integer shape");
}

llvm::Value* create_add(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_add_impl(builder, lhs, rhs, context, salt, name, clamped_depth(context));
}

llvm::Value* create_sub(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_sub_impl(builder, lhs, rhs, context, salt, name, clamped_depth(context));
}

llvm::Value* create_xor(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_xor_impl(builder, lhs, rhs, context, salt, name, clamped_depth(context));
}

llvm::Value* create_mul(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_mul_impl(builder, lhs, rhs, context, salt, name);
}

llvm::Value* create_udiv(llvm::IRBuilder<>& builder,
                         llvm::Value* lhs,
                         llvm::Value* rhs,
                         const builder_context& context,
                         std::uint64_t salt,
                         llvm::StringRef name) {
  return create_udiv_impl(builder, lhs, rhs, context, salt, name);
}

llvm::Value* create_urem(llvm::IRBuilder<>& builder,
                         llvm::Value* lhs,
                         llvm::Value* rhs,
                         const builder_context& context,
                         std::uint64_t salt,
                         llvm::StringRef name) {
  return create_urem_impl(builder, lhs, rhs, context, salt, name);
}

llvm::Value* build_entropy_true_predicate(llvm::IRBuilder<>& builder,
                                          llvm::Function& function,
                                          std::uint32_t mba_depth,
                                          std::uint64_t salt_base,
                                          std::uint64_t context_a_salt,
                                          std::uint64_t context_b_salt,
                                          llvm::StringRef context_a_name,
                                          llvm::StringRef context_b_name,
                                          llvm::StringRef result_name) {
  llvm::Module* module = function.getParent();
  if (module == nullptr) { return nullptr; }

  llvm::GlobalVariable* anchor = get_or_create_entropy_anchor(*module);
  llvm::Value* entropy = builder.CreateLoad(builder.getInt64Ty(), anchor, "obf.opaque.entropy");

  builder_context seed_context =
      get_or_create_builder_context(function, "opaque.seed", salt_base ^ 0x5f3759dfULL);
  builder_context context_a =
      get_or_create_builder_context(function, context_a_name, salt_base ^ context_a_salt);
  builder_context context_b =
      get_or_create_builder_context(function, context_b_name, salt_base ^ context_b_salt);
  seed_context.depth = mba_depth;
  context_a.depth = mba_depth;
  context_b.depth = mba_depth;

  // i anchor both sides to the same seed so this predicate stays true even as the wrappers drift.
  llvm::Value* seed =
      entangle_value(builder, entropy, seed_context, salt_base + 0x11ULL, "obf.opaque.seed");
  llvm::Value* zero_a = create_opaque_integer(builder,
                                              builder.getInt64Ty(),
                                              context_a,
                                              llvm::APInt(64, 0),
                                              salt_base + 0x21ULL,
                                              "obf.opaque.zero.a");
  llvm::Value* expr_a =
      create_add(builder, seed, zero_a, context_a, salt_base + 0x31ULL, "obf.opaque.expr.a");
  llvm::Value* zero_b = create_opaque_integer(builder,
                                              builder.getInt64Ty(),
                                              context_b,
                                              llvm::APInt(64, 0),
                                              salt_base + 0x51ULL,
                                              "obf.opaque.zero.b");
  llvm::Value* expr_b =
      create_xor(builder, seed, zero_b, context_b, salt_base + 0x61ULL, "obf.opaque.expr.b");

  return builder.CreateICmpEQ(expr_a, expr_b, result_name);
}

}  // namespace obf::mba
