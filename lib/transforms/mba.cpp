#include "obf/transforms/mba.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
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

llvm::AllocaInst *find_seed_slot(llvm::Function &function, llvm::StringRef name) {
  for (llvm::Instruction &instruction : function.getEntryBlock()) {
    auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (alloca != nullptr && alloca->getName() == name &&
        alloca->getAllocatedType()->isIntegerTy(64)) {
      return alloca;
    }
  }

  return nullptr;
}

llvm::AllocaInst *get_or_create_seed_slot(llvm::Function &function,
                                          llvm::StringRef name,
                                          std::uint64_t seed) {
  if (llvm::AllocaInst *existing = find_seed_slot(function, name)) {
    return existing;
  }

  llvm::IRBuilder<> builder(&*function.getEntryBlock().getFirstInsertionPt());
  auto *slot = builder.CreateAlloca(builder.getInt64Ty(), nullptr, name);
  auto *store = builder.CreateStore(builder.getInt64(seed), slot);
  store->setVolatile(true);
  return slot;
}

bool is_supported_type(const llvm::Type *type) {
  if (type->isIntegerTy()) {
    return true;
  }

  const auto *vector_type = llvm::dyn_cast<llvm::FixedVectorType>(type);
  return vector_type != nullptr && vector_type->getElementType()->isIntegerTy();
}

llvm::Value *cast_zero_to_type(llvm::IRBuilder<> &builder, llvm::Value *zero64,
                               llvm::Type *target_type) {
  if (auto *integer_type = llvm::dyn_cast<llvm::IntegerType>(target_type)) {
    if (integer_type->getBitWidth() < 64) {
      return builder.CreateTrunc(zero64, integer_type, "obf.mba.zero");
    }

    if (integer_type->getBitWidth() > 64) {
      return builder.CreateZExt(zero64, integer_type, "obf.mba.zero");
    }

    return zero64;
  }

  auto *vector_type = llvm::cast<llvm::FixedVectorType>(target_type);
  auto *element_type = llvm::cast<llvm::IntegerType>(vector_type->getElementType());
  llvm::Value *element_zero = zero64;
  if (element_type->getBitWidth() < 64) {
    element_zero = builder.CreateTrunc(zero64, element_type, "obf.mba.zero.elt");
  } else if (element_type->getBitWidth() > 64) {
    element_zero = builder.CreateZExt(zero64, element_type, "obf.mba.zero.elt");
  }

  return builder.CreateVectorSplat(vector_type->getElementCount(), element_zero,
                                   "obf.mba.zero.vec");
}

llvm::Value *build_opaque_zero(llvm::IRBuilder<> &builder,
                               const builder_context &context,
                               llvm::Type *target_type, std::uint64_t salt) {
  auto *lhs_load = builder.CreateLoad(builder.getInt64Ty(), context.seed_slot_a,
                                      "obf.mba.seed.a");
  lhs_load->setVolatile(true);
  auto *rhs_load = builder.CreateLoad(builder.getInt64Ty(), context.seed_slot_b,
                                      "obf.mba.seed.b");
  rhs_load->setVolatile(true);

  const std::uint64_t salt_word = mix_seed(context.seed_base, salt);
  llvm::Value *mixed_lhs = builder.CreateXor(
      lhs_load, llvm::ConstantInt::get(builder.getInt64Ty(), salt_word),
      "obf.mba.mix.a");
  llvm::Value *mixed_rhs = builder.CreateXor(
      rhs_load, llvm::ConstantInt::get(builder.getInt64Ty(), salt_word),
      "obf.mba.mix.b");
  llvm::Value *zero64 = builder.CreateXor(mixed_lhs, mixed_rhs, "obf.mba.zero64");
  return cast_zero_to_type(builder, zero64, target_type);
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

builder_context get_or_create_builder_context(llvm::Function &function,
                                              llvm::StringRef prefix,
                                              std::uint64_t seed_base) {
  const std::uint64_t seed = derive_function_seed(function, prefix, seed_base);
  const std::string slot_a_name = (prefix + ".seed.a").str();
  const std::string slot_b_name = (prefix + ".seed.b").str();
  return {.seed_slot_a = get_or_create_seed_slot(function, slot_a_name, seed),
          .seed_slot_b = get_or_create_seed_slot(function, slot_b_name, seed),
          .seed_base = seed};
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
