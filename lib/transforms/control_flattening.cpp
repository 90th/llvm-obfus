#include "obf/transforms/control_flattening.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Transforms/Utils/Local.h"

#include <cstddef>
#include <string>
#include <vector>

namespace obf {

namespace {

bool instruction_escapes_block(const llvm::Instruction &instruction) {
  for (const llvm::User *user : instruction.users()) {
    const auto *user_instruction = llvm::dyn_cast<llvm::Instruction>(user);
    if (user_instruction == nullptr) {
      return true;
    }

    if (user_instruction->getParent() != instruction.getParent() ||
        llvm::isa<llvm::PHINode>(user_instruction)) {
      return true;
    }
  }

  return false;
}

bool has_supported_terminators_only(const llvm::Function &function,
                                    std::size_t &conditional_branches) {
  conditional_branches = 0;

  for (const llvm::BasicBlock &block : function) {
    const llvm::Instruction *terminator = block.getTerminator();
    if (terminator == nullptr) {
      return false;
    }

    if (llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(terminator)) {
      if (branch->isConditional()) {
        ++conditional_branches;
      }
      continue;
    }

    return false;
  }

  return true;
}

void hoist_entry_allocas_to_setup(llvm::BasicBlock &entry,
                                  llvm::BasicBlock &setup) {
  llvm::Instruction *insert_before = setup.getTerminator();
  llvm::SmallVector<llvm::AllocaInst *, 8> allocas;

  for (llvm::Instruction &instruction : entry) {
    auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (alloca == nullptr) {
      break;
    }

    allocas.push_back(alloca);
  }

  for (llvm::AllocaInst *alloca : allocas) {
    alloca->moveBefore(insert_before);
  }
}

void demote_phi_nodes(llvm::Function &function, llvm::Instruction *alloca_point) {
  llvm::SmallVector<llvm::PHINode *, 8> phis;
  for (llvm::BasicBlock &block : function) {
    for (llvm::PHINode &phi : block.phis()) {
      phis.push_back(&phi);
    }
  }

  for (llvm::PHINode *phi : phis) {
    llvm::DemotePHIToStack(phi, alloca_point->getIterator());
  }
}

void demote_escaping_registers(llvm::Function &function,
                               llvm::Instruction *alloca_point) {
  llvm::SmallVector<llvm::Instruction *, 32> escaping_values;
  for (llvm::BasicBlock &block : function) {
    for (llvm::Instruction &instruction : block) {
      if (instruction.isTerminator() || instruction.getType()->isVoidTy() ||
          llvm::isa<llvm::AllocaInst>(instruction)) {
        continue;
      }

      if (instruction_escapes_block(instruction)) {
        escaping_values.push_back(&instruction);
      }
    }
  }

  for (llvm::Instruction *instruction : escaping_values) {
    llvm::DemoteRegToStack(*instruction, false, alloca_point->getIterator());
  }
}

} // namespace

control_flattening_result
analyze_control_flattening(const llvm::Function &function,
                           const control_flattening_options &options) {
  if (function.isDeclaration()) {
    return {.flattened = false, .detail = "declaration"};
  }

  if (function.size() < options.min_blocks) {
    return {.flattened = false, .detail = "too few basic blocks"};
  }

  if (function.size() > options.max_blocks) {
    return {.flattened = false, .detail = "too many basic blocks"};
  }

  std::size_t instruction_count = 0;
  for (const llvm::BasicBlock &block : function) {
    if (block.isEHPad()) {
      return {.flattened = false, .detail = "contains EH pad"};
    }

    instruction_count += block.size();
  }

  if (instruction_count > options.max_instructions) {
    return {.flattened = false, .detail = "too many instructions"};
  }

  std::size_t conditional_branches = 0;
  if (!has_supported_terminators_only(function, conditional_branches)) {
    return {.flattened = false, .detail = "unsupported terminator kind"};
  }

  if (conditional_branches == 0) {
    return {.flattened = false, .detail = "no conditional branches"};
  }

  return {.flattened = true,
          .state_count = function.size(),
          .conditional_branches = conditional_branches,
          .detail = std::to_string(function.size()) + " state blocks"};
}

control_flattening_result
run_control_flattening(llvm::Function &function,
                       const control_flattening_options &options) {
  const control_flattening_result analysis =
      analyze_control_flattening(function, options);
  if (!analysis.flattened) {
    return analysis;
  }

  llvm::BasicBlock *original_entry = &function.getEntryBlock();
  llvm::LLVMContext &context = function.getContext();
  llvm::BasicBlock *setup =
      llvm::BasicBlock::Create(context, "obf.flat.setup", &function, original_entry);
  llvm::IRBuilder<> setup_builder(setup);
  llvm::AllocaInst *state_slot =
      setup_builder.CreateAlloca(llvm::Type::getInt32Ty(context), nullptr, "obf.state");
  setup_builder.CreateBr(original_entry);
  hoist_entry_allocas_to_setup(*original_entry, *setup);

  llvm::Instruction *alloca_point = setup->getTerminator();
  demote_phi_nodes(function, alloca_point);
  demote_escaping_registers(function, alloca_point);

  llvm::BasicBlock *dispatch =
      llvm::BasicBlock::Create(context, "obf.flat.dispatch", &function, original_entry);
  setup->getTerminator()->eraseFromParent();
  setup_builder.SetInsertPoint(setup);
  setup_builder.CreateStore(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), 0),
                            state_slot);
  setup_builder.CreateBr(dispatch);

  std::vector<llvm::BasicBlock *> blocks;
  blocks.reserve(function.size());
  for (llvm::BasicBlock &block : function) {
    if (&block != setup && &block != dispatch) {
      blocks.push_back(&block);
    }
  }

  llvm::DenseMap<llvm::BasicBlock *, unsigned> state_ids;
  for (unsigned index = 0; index < blocks.size(); ++index) {
    state_ids[blocks[index]] = index;
  }

  llvm::IRBuilder<> dispatch_builder(dispatch);
  llvm::LoadInst *state_value =
      dispatch_builder.CreateLoad(llvm::Type::getInt32Ty(context), state_slot);
  llvm::SwitchInst *switch_inst =
      dispatch_builder.CreateSwitch(state_value, blocks.front(), blocks.size());
  for (unsigned index = 0; index < blocks.size(); ++index) {
    switch_inst->addCase(
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), index),
        blocks[index]);
  }

  for (llvm::BasicBlock *block : blocks) {
    llvm::Instruction *terminator = block->getTerminator();
    if (llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    llvm::IRBuilder<> builder(terminator);
    if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(terminator)) {
      if (branch->isConditional()) {
        llvm::Value *next_state = builder.CreateSelect(
            branch->getCondition(),
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                   state_ids[branch->getSuccessor(0)]),
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                   state_ids[branch->getSuccessor(1)]));
        builder.CreateStore(next_state, state_slot);
      } else {
        builder.CreateStore(
            llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                   state_ids[branch->getSuccessor(0)]),
            state_slot);
      }

      builder.CreateBr(dispatch);
      terminator->eraseFromParent();
    }
  }

  return {.flattened = true,
          .state_count = analysis.state_count,
          .conditional_branches = analysis.conditional_branches,
          .detail = std::to_string(analysis.state_count) + " state blocks flattened"};
}

} // namespace obf
