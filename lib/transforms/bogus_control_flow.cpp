#include "obf/transforms/bogus_control_flow.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace obf {

namespace {

struct bogus_candidate {
  llvm::BasicBlock *block = nullptr;
  llvm::Value *seed_value = nullptr;
};

llvm::Value *find_opaque_seed_value(llvm::Function &function) {
  for (llvm::Argument &argument : function.args()) {
    if (argument.getType()->isIntegerTy()) {
      return &argument;
    }

    if (argument.getType()->isPointerTy()) {
      return &argument;
    }
  }

  return nullptr;
}

bool is_supported_branch_candidate(llvm::BasicBlock &block) {
  auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
  if (branch == nullptr || !branch->isUnconditional()) {
    return false;
  }

  llvm::BasicBlock *successor = branch->getSuccessor(0);
  return successor != nullptr && successor->phis().empty();
}

bogus_control_flow_result
analyze_impl(const llvm::Function &function,
             const bogus_control_flow_options &options) {
  if (function.isDeclaration()) {
    return {.insertion_count = 0, .detail = "declaration"};
  }

  if (options.max_insertions_per_function == 0) {
    return {.insertion_count = 0,
            .detail = "max_insertions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock &block : function) {
    if (const_cast<llvm::BasicBlock &>(block).phis().empty() &&
        const_cast<llvm::BasicBlock &>(block).getTerminator() != nullptr) {
      if (const_cast<llvm::BasicBlock &>(block).isEHPad()) {
        continue;
      }
      if (const auto *branch =
              llvm::dyn_cast<llvm::BranchInst>(block.getTerminator())) {
        if (branch->isUnconditional() && branch->getSuccessor(0)->phis().empty()) {
          ++count;
          if (count >= options.max_insertions_per_function) {
            return {.insertion_count = count,
                    .detail = std::to_string(count) +
                              " bogus edge(s) available"};
          }
        }
      }
    }
  }

  if (count == 0) {
    return {.insertion_count = 0,
            .detail = "no unconditional branches with phi-free successors"};
  }

  return {.insertion_count = count,
          .detail = std::to_string(count) + " bogus edge(s) available"};
}

} // namespace

bogus_control_flow_result
analyze_bogus_control_flow(const llvm::Function &function,
                           const bogus_control_flow_options &options) {
  return analyze_impl(function, options);
}

bogus_control_flow_result
run_bogus_control_flow(llvm::Function &function,
                       const bogus_control_flow_options &options) {
  const bogus_control_flow_result analysis = analyze_impl(function, options);
  if (analysis.insertion_count == 0) {
    return analysis;
  }

  llvm::Value *seed_value = find_opaque_seed_value(function);
  if (seed_value == nullptr) {
    return {.insertion_count = 0, .detail = "no suitable opaque seed value"};
  }

  std::size_t inserted = 0;
  llvm::SmallVector<llvm::BasicBlock *, 16> blocks;
  for (llvm::BasicBlock &block : function) {
    blocks.push_back(&block);
  }

  for (llvm::BasicBlock *block : blocks) {
    if (inserted >= options.max_insertions_per_function || block == nullptr ||
        !is_supported_branch_candidate(*block)) {
      continue;
    }

    auto *branch = llvm::cast<llvm::BranchInst>(block->getTerminator());
    llvm::BasicBlock *successor = branch->getSuccessor(0);
    llvm::BasicBlock *bogus =
        llvm::BasicBlock::Create(function.getContext(), "obf.bogus", &function,
                                 successor);

    llvm::IRBuilder<> builder(branch);
    llvm::Value *opaque_value = seed_value;
    if (opaque_value->getType()->isPointerTy()) {
      opaque_value = builder.CreatePtrToInt(
          opaque_value, llvm::Type::getInt64Ty(function.getContext()),
          "obf.ptrseed");
    }

    llvm::Value *minus_one = builder.CreateSub(
        opaque_value,
        llvm::ConstantInt::get(opaque_value->getType(), 1), "obf.opaque.dec");
    llvm::Value *product =
        builder.CreateMul(opaque_value, minus_one, "obf.opaque.mul");
    llvm::Value *masked = builder.CreateAnd(
        product, llvm::ConstantInt::get(opaque_value->getType(), 1),
        "obf.opaque.and");
    llvm::Value *predicate = builder.CreateICmpEQ(
        masked, llvm::ConstantInt::get(masked->getType(), 0), "obf.opaque.true");

    llvm::BranchInst *new_branch =
        llvm::BranchInst::Create(successor, bogus, predicate);
    new_branch->insertBefore(branch->getIterator());
    branch->eraseFromParent();

    llvm::IRBuilder<> bogus_builder(bogus);
    llvm::Value *junk = bogus_builder.CreateXor(
        opaque_value,
        llvm::ConstantInt::get(opaque_value->getType(), 0x55aa), "obf.bogus.xor");
    llvm::Value *junk_add = bogus_builder.CreateAdd(
        junk, llvm::ConstantInt::get(opaque_value->getType(), 1), "obf.bogus.add");
    (void)bogus_builder.CreateXor(junk_add,
                                  llvm::ConstantInt::get(opaque_value->getType(), 0x33),
                                  "obf.bogus.mix");
    bogus_builder.CreateBr(successor);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) + " bogus edge(s) inserted"};
}

} // namespace obf
