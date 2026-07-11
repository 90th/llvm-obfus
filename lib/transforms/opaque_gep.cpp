#include "obf/transforms/opaque_gep.h"

#include "obf/support/constant_materialization.h"
#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>

namespace obf {

namespace {

bool constant_contains_gep(const llvm::Constant* constant) {
  const auto* expression = llvm::dyn_cast<llvm::ConstantExpr>(constant);
  if (expression == nullptr) { return false; }

  if (expression->getOpcode() == llvm::Instruction::GetElementPtr) { return true; }

  for (const llvm::Value* operand : expression->operands()) {
    const auto* operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
    if (operand_constant != nullptr && constant_contains_gep(operand_constant)) { return true; }
  }

  return false;
}

std::uint64_t derive_mba_seed(const llvm::Function& function, std::uint64_t option_seed) {
  const std::uint64_t seed = mix_seed(option_seed, stable_hash_string(function.getName()));
  return seed == 0 ? 0x61e1f3b77b6d4c29ULL : seed;
}



bool expand_gep_constant_expressions(llvm::Function& function) {
  llvm::SmallVector<llvm::Instruction*, 64> instructions;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) { instructions.push_back(&instruction); }
  }

  bool changed = false;
  for (llvm::Instruction* instruction : instructions) {
    if (instruction == nullptr) { continue; }

    if (auto* phi = llvm::dyn_cast<llvm::PHINode>(instruction)) {
      for (unsigned incoming_index = 0; incoming_index < phi->getNumIncomingValues();
           ++incoming_index) {
        auto* constant = llvm::dyn_cast<llvm::Constant>(phi->getIncomingValue(incoming_index));
        if (constant == nullptr || !constant_contains_gep(constant)) { continue; }

        llvm::Instruction* insert_before = phi->getIncomingBlock(incoming_index)->getTerminator();
        phi->setIncomingValue(incoming_index,
                              support::materialize_constant_expression(constant, insert_before));
        changed = true;
      }
      continue;
    }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
         ++operand_index) {
      auto* constant = llvm::dyn_cast<llvm::Constant>(instruction->getOperand(operand_index));
      if (constant == nullptr || !constant_contains_gep(constant)) { continue; }

      instruction->setOperand(operand_index,
                              support::materialize_constant_expression(constant, instruction));
      changed = true;
    }
  }

  return changed;
}

opaque_gep_result analyze_impl(const llvm::Function& function) {
  if (function.isDeclaration()) { return {.lowered_count = 0, .detail = "declaration"}; }

  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::GetElementPtrInst>(instruction)) { ++count; }

      if (const auto* phi = llvm::dyn_cast<llvm::PHINode>(&instruction)) {
        for (unsigned incoming_index = 0; incoming_index < phi->getNumIncomingValues();
             ++incoming_index) {
          const auto* constant =
              llvm::dyn_cast<llvm::Constant>(phi->getIncomingValue(incoming_index));
          if (constant != nullptr && constant_contains_gep(constant)) { ++count; }
        }
        continue;
      }

      for (const llvm::Value* operand : instruction.operands()) {
        const auto* constant = llvm::dyn_cast<llvm::Constant>(operand);
        if (constant != nullptr && constant_contains_gep(constant)) { ++count; }
      }
    }
  }

  if (count == 0) { return {.lowered_count = 0, .detail = "no eligible getelementptr uses"}; }

  return {.lowered_count = count,
          .detail = std::to_string(count) + " getelementptr use(s) available"};
}

bool is_supported_gep(const llvm::GetElementPtrInst& instruction,
                      const llvm::DataLayout& data_layout) {
  return instruction.getType()->isPointerTy() &&
         instruction.getPointerOperandType()->isPointerTy() &&
         !data_layout.isNonIntegralPointerType(instruction.getType()) &&
         !data_layout.isNonIntegralPointerType(instruction.getPointerOperandType());
}

llvm::Value* build_scaled_offset_term(llvm::IRBuilder<>& builder,
                                      llvm::Value* index,
                                      llvm::IntegerType* ptr_int_type,
                                      const llvm::APInt& multiplier,
                                      const mba::builder_context& context,
                                      std::uint64_t salt,
                                      std::uint64_t decomposition_bit) {
  llvm::Value* scaled_index = index;
  if (scaled_index->getType() != ptr_int_type) {
    scaled_index = builder.CreateSExtOrTrunc(index, ptr_int_type, "obf.gep.index");
  }

  const llvm::APInt typed_multiplier = multiplier.sextOrTrunc(ptr_int_type->getBitWidth());
  if (typed_multiplier.isOne()) { return scaled_index; }

  if (typed_multiplier.isAllOnes()) {
    return builder.CreateNeg(scaled_index, "obf.gep.scale.neg");
  }

  if (decomposition_bit == 1) {
    const llvm::APInt reduced_multiplier = typed_multiplier - 1;
    llvm::Value* hi = mba::create_mul(builder,
                                      scaled_index,
                                      llvm::ConstantInt::get(ptr_int_type, reduced_multiplier),
                                      context,
                                      salt,
                                      "obf.gep.scale.hi");
    return mba::create_add(builder, hi, scaled_index, context, salt, "obf.gep.scale");
  }

  return mba::create_mul(builder,
                         scaled_index,
                         llvm::ConstantInt::get(ptr_int_type, typed_multiplier),
                         context,
                         salt,
                         "obf.gep.scale");
}

llvm::Value* lower_gep(llvm::GetElementPtrInst& instruction,
                       const opaque_gep_options& options,
                       const mba::builder_context& base_context,
                       std::uint64_t salt) {
  llvm::Function* function = instruction.getFunction();
  llvm::Module* module = function == nullptr ? nullptr : function->getParent();
  if (module == nullptr) { return nullptr; }

  const llvm::DataLayout& data_layout = module->getDataLayout();
  if (!is_supported_gep(instruction, data_layout)) { return nullptr; }

  auto* ptr_int_type = data_layout.getIntPtrType(function->getContext(), instruction.getAddressSpace());
  const unsigned ptr_bit_width = ptr_int_type->getBitWidth();

  for (auto gti = llvm::gep_type_begin(instruction), gte = llvm::gep_type_end(instruction);
       gti != gte; ++gti) {
    if (gti.getStructTypeOrNull() != nullptr) { continue; }
    if (data_layout.getTypeAllocSize(gti.getIndexedType()).isScalable()) { return nullptr; }
  }

  llvm::IRBuilder<> builder(&instruction);
  mba::builder_context mba_context = base_context;
  mba_context.depth = options.mba_depth;
  configure_context_overrides(
      mba_context,
      options.mba_max_ir_instructions,
      options.mba_enable_polynomial,
      options.mba_enable_multiplication);

  llvm::Value* base_ptr = instruction.getPointerOperand();
  llvm::Value* base_int = llvm::CastInst::Create(llvm::Instruction::PtrToInt,
                                                 base_ptr,
                                                 ptr_int_type,
                                                 "obf.gep.base",
                                                 instruction.getIterator());
  llvm::Value* offset_value = mba::create_opaque_integer(
      builder,
      ptr_int_type,
      mba_context,
      llvm::APInt(ptr_bit_width, 0),
      salt,
      "obf.gep.offset.base");

  std::uint64_t local_salt = salt + 1;
  const std::uint64_t seed_base = mba_context.seed_base;
  std::size_t dim = 0;
  for (auto gti = llvm::gep_type_begin(instruction), gte = llvm::gep_type_end(instruction);
       gti != gte; ++gti, ++dim) {
    llvm::Value* term = nullptr;
    if (llvm::StructType* struct_type = gti.getStructTypeOrNull()) {
      const uint64_t field_index =
          llvm::cast<llvm::ConstantInt>(gti.getOperand())->getZExtValue();
      const uint64_t field_offset =
          data_layout.getStructLayout(struct_type)->getElementOffset(
              static_cast<unsigned>(field_index));
      term = mba::create_opaque_integer(builder,
                                        ptr_int_type,
                                        mba_context,
                                        llvm::APInt(ptr_bit_width, field_offset),
                                        local_salt,
                                        "obf.gep.field");
    } else {
      if (data_layout.getTypeAllocSize(gti.getIndexedType()).isScalable()) { return nullptr; }
      const uint64_t elem_size =
          data_layout.getTypeAllocSize(gti.getIndexedType()).getFixedValue();
      term = build_scaled_offset_term(builder,
                                      gti.getOperand(),
                                      ptr_int_type,
                                      llvm::APInt(ptr_bit_width, elem_size),
                                      mba_context,
                                      local_salt,
                                      (mix_seed(seed_base, dim) & 1ULL));
    }

    offset_value =
        mba::create_add(builder, offset_value, term, mba_context, local_salt, "obf.gep.offset");
    ++local_salt;
    offset_value = mba::create_add(
        builder,
        offset_value,
        mba::create_opaque_integer(builder,
                                   ptr_int_type,
                                   mba_context,
                                   llvm::APInt(ptr_bit_width, 0),
                                   local_salt,
                                   "obf.gep.pad"),
        mba_context,
        local_salt ^ 0x5bd1e995ULL,
        "obf.gep.offset");
    ++local_salt;
  }

  llvm::Value* address =
      mba::create_add(builder, base_int, offset_value, mba_context, local_salt, "obf.gep.addr");
  return builder.CreateIntToPtr(address, instruction.getType(), "obf.gep.ptr");
}

}  // namespace

opaque_gep_result analyze_opaque_gep(const llvm::Function& function, const opaque_gep_options&) {
  return analyze_impl(function);
}

opaque_gep_result run_opaque_gep(llvm::Function& function, const opaque_gep_options& options) {
  const opaque_gep_result analysis = analyze_impl(function);
  if (analysis.lowered_count == 0) { return analysis; }

  expand_gep_constant_expressions(function);

  llvm::SmallVector<llvm::GetElementPtrInst*, 32> candidates;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction)) {
        candidates.push_back(gep);
      }
    }
  }

  auto mba_context = obf::support::make_mba_context(
      function, "obf.gep", derive_mba_seed(function, options.seed),
      {options.mba_depth, options.mba_max_ir_instructions, options.mba_enable_polynomial, options.mba_enable_multiplication});

  std::size_t lowered_count = 0;
  std::uint64_t salt = 1;
  for (llvm::GetElementPtrInst* gep : candidates) {
    if (gep == nullptr) { continue; }

    llvm::Value* replacement = lower_gep(*gep, options, mba_context, salt);
    ++salt;
    if (replacement == nullptr) { continue; }

    replacement->takeName(gep);
    gep->replaceAllUsesWith(replacement);
    gep->eraseFromParent();
    ++lowered_count;
  }

  if (lowered_count == 0) {
    return {.lowered_count = 0, .detail = "no getelementptr instructions could be lowered"};
  }

  return {.lowered_count = lowered_count,
          .detail = std::to_string(lowered_count) + " getelementptr instruction(s) lowered"};
}

}  // namespace obf
