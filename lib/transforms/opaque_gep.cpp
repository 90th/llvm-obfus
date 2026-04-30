#include "obf/transforms/opaque_gep.h"

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/MapVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>

namespace obf {

namespace {

bool constant_contains_gep(const llvm::Constant *constant) {
  const auto *expression = llvm::dyn_cast<llvm::ConstantExpr>(constant);
  if (expression == nullptr) {
    return false;
  }

  if (expression->getOpcode() == llvm::Instruction::GetElementPtr) {
    return true;
  }

  for (const llvm::Value *operand : expression->operands()) {
    const auto *operand_constant = llvm::dyn_cast<llvm::Constant>(operand);
    if (operand_constant != nullptr && constant_contains_gep(operand_constant)) {
      return true;
    }
  }

  return false;
}

std::uint64_t derive_mba_seed(const llvm::Function &function) {
  const std::uint64_t seed = stable_hash_string(function.getName());
  return seed == 0 ? 0x61e1f3b77b6d4c29ULL : seed;
}

llvm::Value *materialize_constant_expression(llvm::Value *value,
                                             llvm::Instruction *insert_before) {
  auto *expression = llvm::dyn_cast<llvm::ConstantExpr>(value);
  if (expression == nullptr) {
    return value;
  }

  llvm::Instruction *materialized = expression->getAsInstruction();
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

bool expand_gep_constant_expressions(llvm::Function &function) {
  llvm::SmallVector<llvm::Instruction *, 64> instructions;
  for (llvm::BasicBlock &block : function) {
    for (llvm::Instruction &instruction : block) {
      instructions.push_back(&instruction);
    }
  }

  bool changed = false;
  for (llvm::Instruction *instruction : instructions) {
    if (instruction == nullptr) {
      continue;
    }

    if (auto *phi = llvm::dyn_cast<llvm::PHINode>(instruction)) {
      for (unsigned incoming_index = 0; incoming_index < phi->getNumIncomingValues();
           ++incoming_index) {
        auto *constant =
            llvm::dyn_cast<llvm::Constant>(phi->getIncomingValue(incoming_index));
        if (constant == nullptr || !constant_contains_gep(constant)) {
          continue;
        }

        llvm::Instruction *insert_before =
            phi->getIncomingBlock(incoming_index)->getTerminator();
        phi->setIncomingValue(incoming_index,
                              materialize_constant_expression(constant,
                                                              insert_before));
        changed = true;
      }
      continue;
    }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
         ++operand_index) {
      auto *constant =
          llvm::dyn_cast<llvm::Constant>(instruction->getOperand(operand_index));
      if (constant == nullptr || !constant_contains_gep(constant)) {
        continue;
      }

      instruction->setOperand(
          operand_index,
          materialize_constant_expression(constant, instruction));
      changed = true;
    }
  }

  return changed;
}

opaque_gep_result analyze_impl(const llvm::Function &function) {
  if (function.isDeclaration()) {
    return {.lowered_count = 0, .detail = "declaration"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock &block : function) {
    for (const llvm::Instruction &instruction : block) {
      if (llvm::isa<llvm::GetElementPtrInst>(instruction)) {
        ++count;
      }

      if (const auto *phi = llvm::dyn_cast<llvm::PHINode>(&instruction)) {
        for (unsigned incoming_index = 0; incoming_index < phi->getNumIncomingValues();
             ++incoming_index) {
          const auto *constant =
              llvm::dyn_cast<llvm::Constant>(phi->getIncomingValue(incoming_index));
          if (constant != nullptr && constant_contains_gep(constant)) {
            ++count;
          }
        }
        continue;
      }

      for (const llvm::Value *operand : instruction.operands()) {
        const auto *constant = llvm::dyn_cast<llvm::Constant>(operand);
        if (constant != nullptr && constant_contains_gep(constant)) {
          ++count;
        }
      }
    }
  }

  if (count == 0) {
    return {.lowered_count = 0, .detail = "no eligible getelementptr uses"};
  }

  return {.lowered_count = count,
          .detail = std::to_string(count) + " getelementptr use(s) available"};
}

bool is_supported_gep(const llvm::GetElementPtrInst &instruction,
                      const llvm::DataLayout &data_layout) {
  return instruction.getType()->isPointerTy() &&
         instruction.getPointerOperandType()->isPointerTy() &&
         !data_layout.isNonIntegralPointerType(instruction.getType()) &&
         !data_layout.isNonIntegralPointerType(instruction.getPointerOperandType());
}

llvm::Value *build_scaled_offset_term(llvm::IRBuilder<> &builder, llvm::Value *index,
                                      const llvm::APInt &multiplier) {
  llvm::Value *index64 = index;
  if (!index64->getType()->isIntegerTy(64)) {
    index64 = builder.CreateSExtOrTrunc(index64, builder.getInt64Ty(),
                                        "obf.gep.index");
  }

  const llvm::APInt multiplier64 = multiplier.sextOrTrunc(64);
  if (multiplier64.isOne()) {
    return index64;
  }

  if (multiplier64.isAllOnes()) {
    return builder.CreateNeg(index64, "obf.gep.scale.neg");
  }

  return builder.CreateMul(index64,
                           llvm::ConstantInt::get(builder.getInt64Ty(),
                                                  multiplier64),
                           "obf.gep.scale");
}

llvm::Value *lower_gep(llvm::GetElementPtrInst &instruction,
                       const opaque_gep_options &options,
                       const mba::builder_context &base_context,
                       std::uint64_t salt) {
  llvm::Function *function = instruction.getFunction();
  llvm::Module *module = function == nullptr ? nullptr : function->getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const llvm::DataLayout &data_layout = module->getDataLayout();
  if (!is_supported_gep(instruction, data_layout)) {
    return nullptr;
  }

  llvm::SmallMapVector<llvm::Value *, llvm::APInt, 4> variable_offsets;
  llvm::APInt constant_offset(64, 0);
  if (!instruction.collectOffset(data_layout, 64, variable_offsets,
                                 constant_offset)) {
    return nullptr;
  }

  llvm::IRBuilder<> builder(&instruction);
  mba::builder_context mba_context = base_context;
  mba_context.depth = options.mba_depth;

  llvm::Value *base_ptr = instruction.getPointerOperand();
  llvm::Value *base_int = llvm::CastInst::Create(
      llvm::Instruction::PtrToInt, base_ptr, builder.getInt64Ty(),
      "obf.gep.base", instruction.getIterator());
  llvm::Value *offset_value = mba::create_opaque_integer(
      builder, builder.getInt64Ty(), mba_context, llvm::APInt(64, 0), salt,
      "obf.gep.offset.base");

  std::uint64_t local_salt = salt + 1;
  if (!constant_offset.isZero()) {
    offset_value = mba::create_add(
        builder, offset_value,
        mba::create_opaque_integer(builder, builder.getInt64Ty(), mba_context,
                                   constant_offset.sextOrTrunc(64), local_salt,
                                   "obf.gep.offset.const"),
        mba_context, local_salt ^ 0x35f1e2d7ULL, "obf.gep.offset");
    ++local_salt;
  }

  for (const auto &entry : variable_offsets) {
    llvm::Value *term = build_scaled_offset_term(builder, entry.first,
                                                 entry.second);
    offset_value = mba::create_add(builder, offset_value, term, mba_context,
                                   local_salt, "obf.gep.offset");
    ++local_salt;
  }

  llvm::Value *address = mba::create_add(builder, base_int, offset_value,
                                         mba_context, local_salt,
                                         "obf.gep.addr");
  return builder.CreateIntToPtr(address, instruction.getType(), "obf.gep.ptr");
}

} // namespace

opaque_gep_result analyze_opaque_gep(const llvm::Function &function,
                                     const opaque_gep_options &) {
  return analyze_impl(function);
}

opaque_gep_result run_opaque_gep(llvm::Function &function,
                                 const opaque_gep_options &options) {
  const opaque_gep_result analysis = analyze_impl(function);
  if (analysis.lowered_count == 0) {
    return analysis;
  }

  expand_gep_constant_expressions(function);

  llvm::SmallVector<llvm::GetElementPtrInst *, 32> candidates;
  for (llvm::BasicBlock &block : function) {
    for (llvm::Instruction &instruction : block) {
      if (auto *gep = llvm::dyn_cast<llvm::GetElementPtrInst>(&instruction)) {
        candidates.push_back(gep);
      }
    }
  }

  mba::builder_context mba_context =
      mba::get_or_create_builder_context(function, "obf.gep",
                                         derive_mba_seed(function));
  mba_context.depth = options.mba_depth;

  std::size_t lowered_count = 0;
  std::uint64_t salt = 1;
  for (llvm::GetElementPtrInst *gep : candidates) {
    if (gep == nullptr) {
      continue;
    }

    llvm::Value *replacement = lower_gep(*gep, options, mba_context, salt);
    ++salt;
    if (replacement == nullptr) {
      continue;
    }

    replacement->takeName(gep);
    gep->replaceAllUsesWith(replacement);
    gep->eraseFromParent();
    ++lowered_count;
  }

  if (lowered_count == 0) {
    return {.lowered_count = 0,
            .detail = "no getelementptr instructions could be lowered"};
  }

  return {.lowered_count = lowered_count,
          .detail = std::to_string(lowered_count) +
                    " getelementptr instruction(s) lowered"};
}

} // namespace obf
