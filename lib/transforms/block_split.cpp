#include "obf/transforms/block_split.h"

#include "obf/support/mba_config_builder.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <algorithm>
#include <cstddef>

namespace obf {

namespace {

bool is_supported_terminator(const llvm::Instruction* terminator) {
  return terminator != nullptr && !llvm::isa<llvm::InvokeInst>(terminator) &&
         !llvm::isa<llvm::CallBrInst>(terminator) && !llvm::isa<llvm::CatchSwitchInst>(terminator);
}

llvm::Instruction* select_split_point(llvm::BasicBlock& block,
                                      const block_split_options& options,
                                      std::uint64_t seed) {
  llvm::SmallVector<llvm::Instruction*, 8> candidates;
  std::size_t instruction_count = 0;
  bool retained_prefix_instruction = false;

  for (llvm::Instruction& instruction : block) {
    if (llvm::isa<llvm::PHINode>(instruction)) { continue; }

    ++instruction_count;

    if (!retained_prefix_instruction) {
      retained_prefix_instruction = true;
      continue;
    }

    candidates.push_back(&instruction);
  }

  if (instruction_count < options.min_instructions_per_block || candidates.empty()) {
    return nullptr;
  }

  const std::size_t candidate_index = seed % candidates.size();
  return candidates[candidate_index];
}

}  // namespace

block_split_result analyze_block_split(const llvm::Function& function,
                                       const block_split_options& options,
                                       std::uint64_t seed) {
  if (function.isDeclaration()) { return {.split_count = 0, .detail = "declaration"}; }

  if (options.max_splits_per_function == 0) {
    return {.split_count = 0, .detail = "max_splits_per_function is zero"};
  }

  std::size_t split_count = 0;
  std::size_t block_index = 0;
  for (const llvm::BasicBlock& block : function) {
    if (split_count >= options.max_splits_per_function) { break; }

    const llvm::Instruction* terminator = block.getTerminator();
    if (block.isEHPad() || !is_supported_terminator(terminator)) {
      ++block_index;
      continue;
    }

    llvm::BasicBlock& mutable_block = const_cast<llvm::BasicBlock&>(block);
    llvm::Instruction* split_point =
        select_split_point(mutable_block, options, seed ^ (0x9e3779b97f4a7c15ULL + block_index));
    if (split_point == nullptr) {
      ++block_index;
      continue;
    }

    ++split_count;
    ++block_index;
  }

  if (split_count == 0) { return {.split_count = 0, .detail = "no viable blocks to split"}; }

  return {.split_count = split_count,
          .detail = std::to_string(split_count) + " split(s) available"};
}

block_split_result
run_block_split(llvm::Function& function, const block_split_options& options, std::uint64_t seed) {
  const block_split_result analysis = analyze_block_split(function, options, seed);
  if (analysis.split_count == 0) { return analysis; }

  llvm::SmallVector<llvm::BasicBlock*, 16> original_blocks;
  original_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) { original_blocks.push_back(&block); }

  std::size_t split_count = 0;
  std::size_t block_index = 0;
  for (llvm::BasicBlock* block : original_blocks) {
    if (split_count >= options.max_splits_per_function) { break; }

    if (block == nullptr || block->getParent() != &function || block->isEHPad()) {
      ++block_index;
      continue;
    }

    llvm::Instruction* terminator = block->getTerminator();
    if (!is_supported_terminator(terminator)) {
      ++block_index;
      continue;
    }

    const std::uint64_t block_seed = seed ^ (0x9e3779b97f4a7c15ULL + block_index);
    llvm::Instruction* split_point = select_split_point(*block, options, block_seed);
    if (split_point == nullptr) {
      ++block_index;
      continue;
    }

    llvm::BasicBlock* tail =
        block->splitBasicBlock(split_point->getIterator(), block->getName() + ".obf.split");

    llvm::SmallVector<llvm::Instruction*, 4> live_outs;
    const std::size_t max_live_outs = 1 + static_cast<std::size_t>(block_seed & 1ULL);
    for (llvm::Instruction& instruction : *block) {
      if (live_outs.size() >= max_live_outs) { break; }
      if (instruction.isTerminator() || !instruction.getType()->isIntegerTy()) { continue; }
      bool used_outside = false;
      for (const llvm::User* user : instruction.users()) {
        const auto* user_inst = llvm::dyn_cast<llvm::Instruction>(user);
        if (user_inst != nullptr && user_inst->getParent() != block) {
          used_outside = true;
          break;
        }
      }
      if (used_outside) { live_outs.push_back(&instruction); }
    }

    if (!live_outs.empty()) {
      llvm::LLVMContext& ctx = function.getContext();
      llvm::BasicBlock* bridge =
          llvm::BasicBlock::Create(ctx, block->getName() + ".obf.bridge", &function, tail);
      block->getTerminator()->setSuccessor(0, bridge);
      auto mctx = obf::support::make_mba_context(
          function,
          "obf.split",
          block_seed,
          {options.mba_depth,
           options.mba_max_ir_instructions,
           options.mba_enable_polynomial,
           options.mba_enable_multiplication});
      llvm::IRBuilder<> builder(bridge);
      std::uint64_t site_salt = block_seed;
      for (llvm::Instruction* live_out : live_outs) {
        auto* int_type = llvm::cast<llvm::IntegerType>(live_out->getType());
        llvm::Value* zero = mba::create_opaque_integer(
            builder, int_type, mctx, llvm::APInt(int_type->getBitWidth(), 0), site_salt,
            "obf.split.zero");
        llvm::Value* ident =
            ((site_salt >> 1) & 1ULL) != 0ULL
                ? mba::create_add(builder, live_out, zero, mctx, site_salt, "obf.split.id")
                : mba::create_xor(builder, live_out, zero, mctx, site_salt, "obf.split.id");
        live_out->replaceUsesWithIf(ident, [&](llvm::Use& use) {
          const auto* user_inst = llvm::dyn_cast<llvm::Instruction>(use.getUser());
          return user_inst != nullptr && user_inst->getParent() != block &&
                 user_inst->getParent() != bridge;
        });
        ++site_salt;
      }
      builder.CreateBr(tail);
    }
    ++split_count;
    ++block_index;
  }

  return {.split_count = split_count, .detail = std::to_string(split_count) + " split(s) applied"};
}

}  // namespace obf
