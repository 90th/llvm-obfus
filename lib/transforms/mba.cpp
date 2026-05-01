#include "obf/transforms/mba.h"

#include "obf/support/stable_hash.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/FormatVariadic.h"

#include <cstdint>

namespace obf::mba {

namespace {

enum class opaque_zero_shape {
  xor_pair,
  add_sub_pair,
  sub_pair,
  rotate_xor_pair,
  cmp_select_pair,
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

opaque_zero_shape select_opaque_zero_shape(const builder_context& context, std::uint64_t salt) {
  switch (mix_seed(context.seed_base, salt ^ 0x4f7c2d1b9a031ULL) % 5U) {
    case 0:
      return opaque_zero_shape::xor_pair;
    case 1:
      return opaque_zero_shape::add_sub_pair;
    case 2:
      return opaque_zero_shape::sub_pair;
    case 3:
      return opaque_zero_shape::rotate_xor_pair;
    default:
      return opaque_zero_shape::cmp_select_pair;
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

llvm::Function* get_or_create_entropy_pair_accessor(llvm::Module& module) {
  auto* pair_type = llvm::StructType::get(
      module.getContext(),
      {llvm::Type::getInt64Ty(module.getContext()), llvm::Type::getInt64Ty(module.getContext())});
  if (llvm::Function* existing = module.getFunction("__obf_load_entropy_pair")) {
    if (existing->getReturnType() != pair_type || !existing->arg_empty()) {
      llvm::report_fatal_error("__obf_load_entropy_pair has unexpected signature");
    }
    return existing;
  }

  auto* function_type = llvm::FunctionType::get(pair_type, /*isVarArg=*/false);
  auto* function = llvm::Function::Create(
      function_type, llvm::GlobalValue::ExternalLinkage, "__obf_load_entropy_pair", module);
  function->setDoesNotThrow();
  return function;
}

llvm::AllocaInst* get_or_create_function_entropy_pair_cache(llvm::Function& function,
                                                            llvm::Function& accessor,
                                                            const builder_context& context,
                                                            std::uint64_t salt) {
  auto* pair_type = llvm::dyn_cast<llvm::StructType>(accessor.getReturnType());
  if (pair_type == nullptr) {
    llvm::report_fatal_error("__obf_load_entropy_pair return type is not a struct");
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

  llvm::Function* accessor = get_or_create_entropy_pair_accessor(*module);
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
  llvm::Value* lhs = builder.CreateXor(entropy_a, mask, "obf.mba.zero.xor_pair.lhs");
  llvm::Value* rhs = builder.CreateXor(entropy_b, mask, "obf.mba.zero.xor_pair.rhs");
  return builder.CreateXor(lhs, rhs, "obf.mba.zero.xor_pair");
}

llvm::Value* build_opaque_zero_for_shape(llvm::IRBuilder<>& builder,
                                         opaque_zero_shape shape,
                                         llvm::Value* entropy_a,
                                         llvm::Value* entropy_b,
                                         llvm::Type* target_type,
                                         llvm::Constant* mask,
                                         std::uint64_t salt) {
  switch (shape) {
    case opaque_zero_shape::xor_pair:
      return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
    case opaque_zero_shape::add_sub_pair: {
      llvm::Value* lhs = builder.CreateAdd(entropy_a, mask, "obf.mba.zero.add_sub_pair.lhs");
      llvm::Value* rhs = builder.CreateAdd(entropy_b, mask, "obf.mba.zero.add_sub_pair.rhs");
      return builder.CreateSub(lhs, rhs, "obf.mba.zero.add_sub_pair");
    }
    case opaque_zero_shape::sub_pair: {
      llvm::Value* lhs = builder.CreateXor(entropy_a, mask, "obf.mba.zero.sub_pair.lhs");
      llvm::Value* rhs = builder.CreateXor(entropy_b, mask, "obf.mba.zero.sub_pair.rhs");
      return builder.CreateSub(lhs, rhs, "obf.mba.zero.sub_pair");
    }
    case opaque_zero_shape::rotate_xor_pair: {
      if (!target_type->isIntegerTy()) {
        return build_opaque_zero_xor_pair(builder, entropy_a, entropy_b, mask);
      }

      llvm::Value* lhs_seed =
          builder.CreateXor(entropy_a, mask, "obf.mba.zero.rotate_xor_pair.lhs.seed");
      llvm::Value* rhs_seed =
          builder.CreateXor(entropy_b, mask, "obf.mba.zero.rotate_xor_pair.rhs.seed");
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
      return builder.CreateSelect(
          equal, llvm::Constant::getNullValue(target_type), delta, "obf.mba.zero.cmp_select_pair");
    }
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

  const bool use_or_and = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_or_and) {
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

  const bool use_borrow = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_borrow) {
    llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.mba.sub.xor");
    llvm::Value* borrow_mask = builder.CreateAnd(
        builder.CreateNot(lhs, "obf.mba.sub.notlhs"), rhs, "obf.mba.sub.borrow.mask");
    llvm::Value* borrow = builder.CreateAdd(
        borrow_mask,
        mask_with_zero_xor(builder, borrow_mask, context, salt + 0x53, "obf.mba.sub.borrow.masked"),
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

  llvm::Value* lhs_only =
      builder.CreateAnd(lhs, builder.CreateNot(rhs, "obf.mba.sub.notrhs"), "obf.mba.sub.lhs.only");
  llvm::Value* rhs_only =
      builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.sub.notlhs2"), rhs, "obf.mba.sub.rhs.only");
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

  const bool use_or_sub = (mix_seed(context.seed_base, salt) & 1U) == 0;
  if (use_or_sub) {
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

  llvm::Value* lhs_only =
      builder.CreateAnd(lhs, builder.CreateNot(rhs, "obf.mba.xor.notrhs"), "obf.mba.xor.lhs.only");
  llvm::Value* rhs_only =
      builder.CreateAnd(builder.CreateNot(lhs, "obf.mba.xor.notlhs"), rhs, "obf.mba.xor.rhs.only");
  llvm::Value* masked_lhs =
      mask_with_zero_xor(builder, lhs_only, context, salt + 0xa3, "obf.mba.xor.left.mask");
  llvm::Value* masked_rhs =
      mask_with_zero_add(builder, rhs_only, context, salt + 0xb1, "obf.mba.xor.right.mask");
  // OR has no MBA equivalent — stays as a plain CreateOr at all depths.
  return builder.CreateOr(masked_lhs, masked_rhs, name.empty() ? "obf.mba.xor" : name);
}

}  // namespace

llvm::GlobalVariable* get_or_create_entropy_anchor(llvm::Module& module) {
  if (llvm::GlobalVariable* existing = module.getNamedGlobal("__obf_entropy_anchor")) {
    return existing;
  }

  auto* anchor = new llvm::GlobalVariable(module,
                                          llvm::Type::getInt64Ty(module.getContext()),
                                          /*isConstant=*/false,
                                          llvm::GlobalValue::ExternalLinkage,
                                          /*Initializer=*/nullptr,
                                          "__obf_entropy_anchor");
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
  return entangle_value_impl(builder,
                             llvm::ConstantInt::get(type, value),
                             context,
                             salt,
                             name.empty() ? "obf.seed" : name);
}

llvm::Value* create_add(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_add_impl(
      builder, lhs, rhs, context, salt, name, std::min(context.depth, max_mba_depth));
}

llvm::Value* create_sub(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_sub_impl(
      builder, lhs, rhs, context, salt, name, std::min(context.depth, max_mba_depth));
}

llvm::Value* create_xor(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name) {
  return create_xor_impl(
      builder, lhs, rhs, context, salt, name, std::min(context.depth, max_mba_depth));
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

  builder_context context_a =
      get_or_create_builder_context(function, context_a_name, salt_base ^ context_a_salt);
  builder_context context_b =
      get_or_create_builder_context(function, context_b_name, salt_base ^ context_b_salt);
  context_a.depth = mba_depth;
  context_b.depth = mba_depth;

  llvm::Value* seed_a =
      entangle_value(builder, entropy, context_a, salt_base + 0x11ULL, "obf.opaque.seed.a");
  llvm::Value* zero_a = create_opaque_integer(builder,
                                              builder.getInt64Ty(),
                                              context_a,
                                              llvm::APInt(64, 0),
                                              salt_base + 0x21ULL,
                                              "obf.opaque.zero.a");
  llvm::Value* expr_a =
      create_add(builder, seed_a, zero_a, context_a, salt_base + 0x31ULL, "obf.opaque.expr.a");

  llvm::Value* seed_b =
      entangle_value(builder, entropy, context_b, salt_base + 0x41ULL, "obf.opaque.seed.b");
  llvm::Value* zero_b = create_opaque_integer(builder,
                                              builder.getInt64Ty(),
                                              context_b,
                                              llvm::APInt(64, 0),
                                              salt_base + 0x51ULL,
                                              "obf.opaque.zero.b");
  llvm::Value* expr_b =
      create_xor(builder, seed_b, zero_b, context_b, salt_base + 0x61ULL, "obf.opaque.expr.b");

  return builder.CreateICmpEQ(expr_a, expr_b, result_name);
}

}  // namespace obf::mba
