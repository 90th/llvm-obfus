#include "obf/transforms/mba.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <cstdint>

namespace obf::mba {

namespace {

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_function_seed(const llvm::Function &function,
                                   llvm::StringRef prefix,
                                   std::uint64_t seed_base) {
  std::uint64_t seed = seed_base;
  seed = mix_seed(seed,
                  static_cast<std::uint64_t>(llvm::hash_value(function.getName())));
  seed = mix_seed(seed,
                  static_cast<std::uint64_t>(llvm::hash_value(prefix)));
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

bool is_supported_type(const llvm::Type *type) {
  if (type->isIntegerTy()) {
    return true;
  }

  const auto *vector_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
  return vector_type != nullptr && vector_type->getElementType()->isIntegerTy();
}

llvm::Value *cast_i64_to_type(llvm::IRBuilder<> &builder, llvm::Value *value64,
                              llvm::Type *target_type, llvm::StringRef name_prefix) {
  if (auto *integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    if (integer_type->getBitWidth() < 64) {
      return builder.CreateTrunc(value64, integer_type,
                                 (name_prefix + ".trunc").str());
    }

    if (integer_type->getBitWidth() > 64) {
      return builder.CreateZExt(value64, integer_type,
                                (name_prefix + ".zext").str());
    }

    return value64;
  }

  auto *vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto *element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Value *element_value = value64;
  if (element_type->getBitWidth() < 64) {
    element_value = builder.CreateTrunc(value64, element_type,
                                        (name_prefix + ".elt.trunc").str());
  } else if (element_type->getBitWidth() > 64) {
    element_value = builder.CreateZExt(value64, element_type,
                                       (name_prefix + ".elt.zext").str());
  }

  return builder.CreateVectorSplat(vector_type->getElementCount(), element_value,
                                   (name_prefix + ".vec").str());
}

llvm::Constant *constant_i64_to_type(llvm::Type *target_type, std::uint64_t word) {
  if (auto *integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    return llvm::ConstantInt::get(
        integer_type,
        llvm::APInt(integer_type->getBitWidth(), word, false, true));
  }

  auto *vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto *element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Constant *element = llvm::ConstantInt::get(
      element_type,
      llvm::APInt(element_type->getBitWidth(), word, false, true));
  return llvm::ConstantVector::getSplat(vector_type->getElementCount(), element);
}

llvm::GlobalVariable *get_or_create_entropy_anchor_ref(llvm::Module &module) {
  if (llvm::GlobalVariable *existing =
          module.getNamedGlobal("__obf_entropy_anchor_ref")) {
    return existing;
  }

  auto *ref = new llvm::GlobalVariable(
      module, llvm::PointerType::get(module.getContext(), 0),
      /*isConstant=*/false, llvm::GlobalValue::ExternalLinkage,
      /*Initializer=*/nullptr, "__obf_entropy_anchor_ref");
  ref->setExternallyInitialized(true);
  ref->setAlignment(llvm::Align(8));
  return ref;
}

struct entropy_pair {
  llvm::Value *direct = nullptr;
  llvm::Value *indirect = nullptr;
};

entropy_pair load_entropy_anchor_pair(llvm::IRBuilder<> &builder,
                                      llvm::GlobalVariable *entropy_anchor,
                                      llvm::StringRef name) {
  llvm::Module *module = entropy_anchor->getParent();
  auto *anchor_ref = get_or_create_entropy_anchor_ref(*module);
  llvm::Value *direct = builder.CreateLoad(builder.getInt64Ty(), entropy_anchor,
                                           (name + ".direct").str());
  llvm::Value *ref_ptr = builder.CreateLoad(anchor_ref->getValueType(), anchor_ref,
                                            (name + ".ref").str());
  builder.CreateStore(direct, ref_ptr);
  llvm::Value *indirect = builder.CreateLoad(builder.getInt64Ty(), entropy_anchor,
                                             (name + ".indirect").str());
  return {.direct = direct, .indirect = indirect};
}

llvm::Value *entangle_value_impl(llvm::IRBuilder<> &builder, llvm::Value *value,
                                 const builder_context &context,
                                 std::uint64_t salt, llvm::StringRef name);

llvm::Value *build_opaque_zero(llvm::IRBuilder<> &builder,
                               const builder_context &context,
                               llvm::Type *target_type, std::uint64_t salt) {
  if (context.entropy_anchor == nullptr || !is_supported_type(target_type)) {
    return llvm::Constant::getNullValue(target_type);
  }

  const entropy_pair entropy =
      load_entropy_anchor_pair(builder, context.entropy_anchor, "obf.entropy");
  llvm::Value *entropy_a =
      cast_i64_to_type(builder, entropy.direct, target_type, "obf.entropy.a.cast");
  llvm::Value *entropy_b =
      cast_i64_to_type(builder, entropy.indirect, target_type, "obf.entropy.b.cast");
  llvm::Constant *mask = constant_i64_to_type(
      target_type, mix_seed(context.seed_base, salt ^ 0x13579bdfULL));
  llvm::Value *lhs = builder.CreateXor(entropy_a, mask, "obf.entropy.mix.a");
  llvm::Value *rhs = builder.CreateXor(entropy_b, mask, "obf.entropy.mix.b");
  return builder.CreateXor(lhs, rhs, "obf.mba.zero");
}

llvm::Value *entangle_value_impl(llvm::IRBuilder<> &builder, llvm::Value *value,
                                 const builder_context &context,
                                 std::uint64_t salt, llvm::StringRef name) {
  if (context.entropy_anchor == nullptr || !is_supported_type(value->getType())) {
    return value;
  }

  const entropy_pair entropy =
      load_entropy_anchor_pair(builder, context.entropy_anchor, "obf.entropy");
  llvm::Value *entropy_a =
      cast_i64_to_type(builder, entropy.direct, value->getType(), "obf.entropy.a.cast");
  llvm::Value *entropy_b =
      cast_i64_to_type(builder, entropy.indirect, value->getType(), "obf.entropy.b.cast");

  llvm::Constant *mask = constant_i64_to_type(
      value->getType(), mix_seed(context.seed_base, salt ^ 0x13579bdfULL));
  llvm::Value *left = builder.CreateXor(
      value, builder.CreateXor(entropy_a, mask, "obf.entropy.mix.a"),
      "obf.entropy.left");
  return builder.CreateXor(
      left, builder.CreateXor(entropy_b, mask, "obf.entropy.mix.b"),
      name.empty() ? "obf.entropy.value" : name);
}

llvm::Value *mask_with_zero_add(llvm::IRBuilder<> &builder, llvm::Value *value,
                                const builder_context &context,
                                std::uint64_t salt, llvm::StringRef name) {
  return builder.CreateAdd(value,
                           build_opaque_zero(builder, context, value->getType(), salt),
                           name);
}

llvm::Value *mask_with_zero_xor(llvm::IRBuilder<> &builder, llvm::Value *value,
                                const builder_context &context,
                                std::uint64_t salt, llvm::StringRef name) {
  return builder.CreateXor(value,
                           build_opaque_zero(builder, context, value->getType(), salt),
                           name);
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

llvm::Value *create_add_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value *create_sub_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value *create_xor_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth);

llvm::Value *create_add_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateAdd(lhs, rhs, name.empty() ? "obf.mba.add" : name);
  }

  const bool use_or_and = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_or_and) {
    llvm::Value *or_part = builder.CreateOr(lhs, rhs, "obf.mba.add.or");
    llvm::Value *and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.and");
    llvm::Value *lhs_term =
        mask_with_zero_add(builder, or_part, context, salt + 0x11,
                           "obf.mba.add.left");
    llvm::Value *rhs_term =
        mask_with_zero_xor(builder, and_part, context, salt + 0x29,
                           "obf.mba.add.right");
    return create_add_impl(builder, lhs_term, rhs_term, context,
                           mix_seed(salt, 0xd1ULL * remaining_depth), name,
                           remaining_depth - 1);
  }

  llvm::Value *xor_part = builder.CreateXor(lhs, rhs, "obf.mba.add.xor");
  llvm::Value *and_part = builder.CreateAnd(lhs, rhs, "obf.mba.add.and");
  llvm::Value *carry = builder.CreateAdd(
      and_part, mask_with_zero_xor(builder, and_part, context, salt + 0x3d,
                                   "obf.mba.add.carry.mask"),
      "obf.mba.add.carry");
  llvm::Value *masked_xor =
      mask_with_zero_add(builder, xor_part, context, salt + 0x47,
                         "obf.mba.add.xor.mask");
  return create_add_impl(builder, masked_xor, carry, context,
                         mix_seed(salt, 0xd2ULL * remaining_depth), name,
                         remaining_depth - 1);
}

llvm::Value *create_sub_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateSub(lhs, rhs, name.empty() ? "obf.mba.sub" : name);
  }

  const bool use_borrow = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_borrow) {
    llvm::Value *xor_part = builder.CreateXor(lhs, rhs, "obf.mba.sub.xor");
    llvm::Value *borrow_mask =
        builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.sub.notlhs"), rhs,
                          "obf.mba.sub.borrow.mask");
    llvm::Value *borrow = builder.CreateAdd(
        borrow_mask,
        mask_with_zero_xor(builder, borrow_mask, context, salt + 0x53,
                           "obf.mba.sub.borrow.masked"),
        "obf.mba.sub.borrow");
    llvm::Value *masked_xor =
        mask_with_zero_add(builder, xor_part, context, salt + 0x61,
                           "obf.mba.sub.xor.mask");
    return create_sub_impl(builder, masked_xor, borrow, context,
                           mix_seed(salt, 0xe1ULL * remaining_depth), name,
                           remaining_depth - 1);
  }

  llvm::Value *lhs_only =
      builder.CreateAnd(lhs, builder.CreateNot(rhs, "obf.mba.sub.notrhs"),
                        "obf.mba.sub.lhs.only");
  llvm::Value *rhs_only =
      builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.sub.notlhs2"), rhs,
                        "obf.mba.sub.rhs.only");
  llvm::Value *masked_lhs =
      mask_with_zero_xor(builder, lhs_only, context, salt + 0x73,
                         "obf.mba.sub.left");
  llvm::Value *masked_rhs =
      mask_with_zero_add(builder, rhs_only, context, salt + 0x79,
                         "obf.mba.sub.right");
  return create_sub_impl(builder, masked_lhs, masked_rhs, context,
                         mix_seed(salt, 0xe2ULL * remaining_depth), name,
                         remaining_depth - 1);
}

llvm::Value *create_xor_impl(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                             llvm::Value *rhs, const builder_context &context,
                             std::uint64_t salt, llvm::StringRef name,
                             std::uint32_t remaining_depth) {
  if (remaining_depth == 0 || !is_supported_type(lhs->getType()) ||
      lhs->getType() != rhs->getType()) {
    return builder.CreateXor(lhs, rhs, name.empty() ? "obf.mba.xor" : name);
  }

  const bool use_or_sub = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_or_sub) {
    llvm::Value *or_part = builder.CreateOr(lhs, rhs, "obf.mba.xor.or");
    llvm::Value *and_part = builder.CreateAnd(lhs, rhs, "obf.mba.xor.and");
    llvm::Value *masked_or =
        mask_with_zero_add(builder, or_part, context, salt + 0x89,
                           "obf.mba.xor.left");
    llvm::Value *masked_and =
        mask_with_zero_xor(builder, and_part, context, salt + 0x97,
                           "obf.mba.xor.right");
    return create_sub_impl(builder, masked_or, masked_and, context,
                           mix_seed(salt, 0xf1ULL * remaining_depth), name,
                           remaining_depth - 1);
  }

  llvm::Value *lhs_only =
      builder.CreateAnd(lhs, builder.CreateNot(rhs, "obf.mba.xor.notrhs"),
                        "obf.mba.xor.lhs.only");
  llvm::Value *rhs_only =
      builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.xor.notlhs"), rhs,
                        "obf.mba.xor.rhs.only");
  llvm::Value *masked_lhs =
      mask_with_zero_xor(builder, lhs_only, context, salt + 0xa3,
                         "obf.mba.xor.left.mask");
  llvm::Value *masked_rhs =
      mask_with_zero_add(builder, rhs_only, context, salt + 0xb1,
                         "obf.mba.xor.right.mask");
  // OR has no MBA equivalent — stays as a plain CreateOr at all depths.
  return builder.CreateOr(masked_lhs, masked_rhs,
                          name.empty() ? "obf.mba.xor" : name);
}

} // namespace

llvm::GlobalVariable *get_or_create_entropy_anchor(llvm::Module &module) {
  if (llvm::GlobalVariable *existing =
          module.getNamedGlobal("__obf_entropy_anchor")) {
    return existing;
  }

  auto *anchor = new llvm::GlobalVariable(
      module, llvm::Type::getInt64Ty(module.getContext()), /*isConstant=*/false,
      llvm::GlobalValue::ExternalLinkage,
      /*Initializer=*/nullptr,
      "__obf_entropy_anchor");
  anchor->setExternallyInitialized(true);
  anchor->setAlignment(llvm::Align(8));
  return anchor;
}

builder_context get_or_create_builder_context(llvm::Function &function,
                                              llvm::StringRef prefix,
                                              std::uint64_t seed_base) {
  llvm::Module *module = function.getParent();
  return {.entropy_anchor = module == nullptr ? nullptr
                                              : get_or_create_entropy_anchor(*module),
          .seed_base = derive_function_seed(function, prefix, seed_base)};
}

llvm::Value *entangle_value(llvm::IRBuilder<> &builder, llvm::Value *value,
                            const builder_context &context,
                            std::uint64_t salt, llvm::StringRef name) {
  return entangle_value_impl(builder, value, context, salt, name);
}

llvm::Value *create_opaque_integer(llvm::IRBuilder<> &builder,
                                   llvm::IntegerType *type,
                                   const builder_context &context,
                                   const llvm::APInt &value,
                                   std::uint64_t salt,
                                   llvm::StringRef name) {
  return entangle_value_impl(builder, llvm::ConstantInt::get(type, value), context,
                             salt, name.empty() ? "obf.seed" : name);
}

llvm::Value *create_add(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name) {
  return create_add_impl(builder, lhs, rhs, context, salt, name,
                         std::min(context.depth, max_mba_depth));
}

llvm::Value *create_sub(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name) {
  return create_sub_impl(builder, lhs, rhs, context, salt, name,
                         std::min(context.depth, max_mba_depth));
}

llvm::Value *create_xor(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name) {
  return create_xor_impl(builder, lhs, rhs, context, salt, name,
                         std::min(context.depth, max_mba_depth));
}

} // namespace obf::mba
