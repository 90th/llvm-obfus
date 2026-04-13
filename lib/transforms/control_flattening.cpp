#include "obf/transforms/control_flattening.h"

#include "obf/transforms/mba.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace obf {

namespace {

struct carried_value {
  llvm::Value *original = nullptr;
  llvm::PHINode *dispatcher_phi = nullptr;
};

struct transition_edge {
  llvm::BasicBlock *source = nullptr;
  llvm::BasicBlock *successor = nullptr;
  llvm::BasicBlock *block = nullptr;
  llvm::Value *next_state = nullptr;
};

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

llvm::Value *encode_state_id(llvm::IRBuilder<> &builder, llvm::Function &function,
                             const mba::builder_context &base_context,
                             std::uint64_t salt, unsigned state_id) {
  mba::builder_context context = base_context;
  context.depth = std::max<std::uint32_t>(context.depth, 2);
  llvm::Value *encoded_state = mba::create_opaque_integer(
      builder, builder.getInt32Ty(), context,
      llvm::APInt(32, static_cast<std::uint64_t>(state_id)), salt,
      "obf.flat.state.opaque");
  llvm::Value *encoded_zero = mba::create_opaque_integer(
      builder, builder.getInt32Ty(), context, llvm::APInt(32, 0),
      salt ^ 0x9e3779b9ULL, "obf.flat.state.zero");
  return mba::create_add(builder, encoded_state, encoded_zero, context,
                         salt ^ 0xa55aa55aULL, "obf.flat.state.next");
}

llvm::Value *translate_value_for_edge(
    llvm::Value *value, llvm::BasicBlock *source, llvm::BasicBlock *successor,
    const llvm::DenseMap<llvm::Value *, llvm::PHINode *> &dispatcher_phis) {
  if (auto *phi = llvm::dyn_cast<llvm::PHINode>(value)) {
    if (phi->getParent() == successor) {
      return translate_value_for_edge(phi->getIncomingValueForBlock(source), source,
                                      successor, dispatcher_phis);
    }

    if (const auto it = dispatcher_phis.find(phi); it != dispatcher_phis.end()) {
      return it->second;
    }

    return phi;
  }

  auto *instruction = llvm::dyn_cast<llvm::Instruction>(value);
  if (instruction == nullptr) {
    return value;
  }

  if (instruction->getParent() == source) {
    return instruction;
  }

  if (const auto it = dispatcher_phis.find(instruction);
      it != dispatcher_phis.end()) {
    return it->second;
  }

  return instruction;
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
  llvm::BasicBlock *dispatch = llvm::BasicBlock::Create(
      context, "obf.flat.dispatch", &function, original_entry);
  llvm::IRBuilder<> setup_builder(setup);
  setup_builder.CreateBr(dispatch);
  hoist_entry_allocas_to_setup(*original_entry, *setup);

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

  std::vector<carried_value> carried_values;
  carried_values.reserve(blocks.size());
  std::vector<llvm::PHINode *> original_phis;
  for (llvm::BasicBlock *block : blocks) {
    for (llvm::Instruction &instruction : *block) {
      if (auto *phi = llvm::dyn_cast<llvm::PHINode>(&instruction)) {
        original_phis.push_back(phi);
        carried_values.push_back({.original = phi});
        continue;
      }

      if (instruction.isTerminator() || instruction.getType()->isVoidTy() ||
          llvm::isa<llvm::AllocaInst>(instruction)) {
        continue;
      }

      if (instruction_escapes_block(instruction)) {
        carried_values.push_back({.original = &instruction});
      }
    }
  }

  llvm::PHINode *state_phi = llvm::PHINode::Create(
      llvm::Type::getInt32Ty(context), 1, "obf.state", dispatch);
  llvm::DenseMap<llvm::Value *, llvm::PHINode *> dispatcher_phis;
  for (carried_value &carried : carried_values) {
    auto *phi = llvm::PHINode::Create(carried.original->getType(), 1,
                                      "obf.flat.val", dispatch);
    carried.dispatcher_phi = phi;
    dispatcher_phis[carried.original] = phi;
  }

  for (const carried_value &carried : carried_values) {
    llvm::SmallVector<llvm::Use *, 8> escaping_uses;
    for (llvm::Use &use : carried.original->uses()) {
      escaping_uses.push_back(&use);
    }

    auto *instruction = llvm::cast<llvm::Instruction>(carried.original);
    for (llvm::Use *use : escaping_uses) {
      auto *user_instruction = llvm::dyn_cast<llvm::Instruction>(use->getUser());
      if (user_instruction == nullptr) {
        use->set(carried.dispatcher_phi);
        continue;
      }

      const bool replace_use = llvm::isa<llvm::PHINode>(instruction) ||
                               llvm::isa<llvm::PHINode>(user_instruction) ||
                               user_instruction->getParent() != instruction->getParent();
      if (replace_use) {
        use->set(carried.dispatcher_phi);
      }
    }
  }

  mba::builder_context mba_context =
      mba::get_or_create_builder_context(function, "obf.flat", 0x2f4d8f13ULL);

  std::vector<transition_edge> transition_edges;
  transition_edges.reserve(blocks.size() * 2);
  std::uint64_t transition_salt = 0x6137c4d9ULL;
  for (llvm::BasicBlock *block : blocks) {
    llvm::Instruction *terminator = block->getTerminator();
    if (llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    auto *branch = llvm::cast<llvm::BranchInst>(terminator);
    llvm::SmallVector<transition_edge, 2> block_edges;
    for (unsigned successor_index = 0; successor_index < branch->getNumSuccessors();
         ++successor_index) {
      llvm::BasicBlock *successor = branch->getSuccessor(successor_index);
      llvm::BasicBlock *edge_block = llvm::BasicBlock::Create(
          context, "obf.flat.edge", &function, dispatch);
      llvm::IRBuilder<> edge_builder(edge_block);
      llvm::Value *next_state = encode_state_id(
          edge_builder, function, mba_context,
          transition_salt + static_cast<std::uint64_t>(transition_edges.size() + 1),
          state_ids[successor]);
      edge_builder.CreateBr(dispatch);
      block_edges.push_back({.source = block,
                             .successor = successor,
                             .block = edge_block,
                             .next_state = next_state});
    }

    llvm::IRBuilder<> builder(branch);
    if (branch->isConditional()) {
      builder.CreateCondBr(branch->getCondition(), block_edges[0].block,
                           block_edges[1].block);
    } else {
      builder.CreateBr(block_edges[0].block);
    }
    branch->eraseFromParent();

    transition_edges.insert(transition_edges.end(), block_edges.begin(),
                            block_edges.end());
  }

  setup_builder.SetInsertPoint(setup->getTerminator());
  state_phi->addIncoming(encode_state_id(setup_builder, function, mba_context,
                                         0x13579bdfULL,
                                         state_ids[original_entry]),
                         setup);
  for (const carried_value &carried : carried_values) {
    carried.dispatcher_phi->addIncoming(llvm::PoisonValue::get(carried.original->getType()),
                                        setup);
  }

  for (const transition_edge &edge : transition_edges) {
    state_phi->addIncoming(edge.next_state, edge.block);
    for (const carried_value &carried : carried_values) {
      carried.dispatcher_phi->addIncoming(
          translate_value_for_edge(carried.original, edge.source, edge.successor,
                                   dispatcher_phis),
          edge.block);
    }
  }

  for (llvm::PHINode *phi : original_phis) {
    phi->eraseFromParent();
  }

  llvm::IRBuilder<> dispatch_builder(dispatch);
  llvm::SwitchInst *switch_inst =
      dispatch_builder.CreateSwitch(state_phi, blocks.front(), blocks.size());
  for (unsigned index = 0; index < blocks.size(); ++index) {
    switch_inst->addCase(
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), index),
        blocks[index]);
  }

  return {.flattened = true,
          .state_count = analysis.state_count,
          .conditional_branches = analysis.conditional_branches,
          .detail = std::to_string(analysis.state_count) + " state blocks flattened"};
}

} // namespace obf
