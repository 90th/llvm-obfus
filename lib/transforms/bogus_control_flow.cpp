#include "obf/transforms/bogus_control_flow.h"

#include "obf/transforms/mba.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>

namespace obf {

namespace {

constexpr std::uint32_t dse_trap_iterations = 1000000U;

bool is_supported_branch_candidate(llvm::BasicBlock &block) {
  auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
  if (branch == nullptr || !branch->isUnconditional()) {
    return false;
  }

  llvm::BasicBlock *successor = branch->getSuccessor(0);
  return successor != nullptr && successor->phis().empty();
}

void populate_dse_trap(llvm::Function &function, llvm::BasicBlock &bogus,
                       llvm::BasicBlock &sink) {
  llvm::LLVMContext &context = function.getContext();
  llvm::BasicBlock *loop = llvm::BasicBlock::Create(context, "obf.bogus.loop",
                                                    &function, &sink);

  llvm::IRBuilder<> bogus_builder(&bogus);
  llvm::Value *initial_entropy = bogus_builder.CreateLoad(
      bogus_builder.getInt64Ty(),
      mba::get_or_create_entropy_anchor(*function.getParent()),
      "obf.bogus.seed");
  llvm::Value *initial_state = bogus_builder.CreateXor(
      initial_entropy,
      llvm::ConstantInt::get(bogus_builder.getInt64Ty(), 0xd6e8feb86659fd93ULL),
      "obf.bogus.state.init");
  bogus_builder.CreateBr(loop);

  llvm::IRBuilder<> loop_builder(loop);
  llvm::PHINode *iteration =
      loop_builder.CreatePHI(loop_builder.getInt32Ty(), 2, "obf.bogus.iter");
  llvm::PHINode *state =
      loop_builder.CreatePHI(loop_builder.getInt64Ty(), 2, "obf.bogus.state");
  llvm::Value *rotl_shl = loop_builder.CreateShl(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 13),
      "obf.bogus.rotl.shl");
  llvm::Value *rotl_lshr = loop_builder.CreateLShr(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 51),
      "obf.bogus.rotl.lshr");
  llvm::Value *rotl = loop_builder.CreateOr(rotl_shl, rotl_lshr,
                                            "obf.bogus.rotl");
  llvm::Value *mixed = loop_builder.CreateXor(
      rotl, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x9e3779b97f4a7c15ULL),
      "obf.bogus.mix");
  llvm::Value *multiplied = loop_builder.CreateMul(
      mixed,
      llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x94d049bb133111ebULL),
      "obf.bogus.mul");
  llvm::Value *iteration64 =
      loop_builder.CreateZExt(iteration, loop_builder.getInt64Ty(),
                              "obf.bogus.iter64");
  llvm::Value *next_state = loop_builder.CreateXor(
      multiplied, iteration64, "obf.bogus.state.next");
  llvm::Value *next_iteration = loop_builder.CreateAdd(
      iteration, llvm::ConstantInt::get(loop_builder.getInt32Ty(), 1),
      "obf.bogus.iter.next");
  llvm::Value *done = loop_builder.CreateICmpEQ(
      next_iteration,
      llvm::ConstantInt::get(loop_builder.getInt32Ty(), dse_trap_iterations),
      "obf.bogus.done");
  loop_builder.CreateCondBr(done, &sink, loop);

  iteration->addIncoming(llvm::ConstantInt::get(loop_builder.getInt32Ty(), 0),
                         &bogus);
  iteration->addIncoming(next_iteration, loop);
  state->addIncoming(initial_state, &bogus);
  state->addIncoming(next_state, loop);

  llvm::IRBuilder<> sink_builder(&sink);
  sink_builder.CreateBr(sink.getNextNode());
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
    llvm::BasicBlock *sink = llvm::BasicBlock::Create(
        function.getContext(), "obf.bogus.sink", &function, successor);

    llvm::IRBuilder<> builder(branch);
    llvm::Value *predicate = mba::build_entropy_true_predicate(
      builder, function, options.mba_depth,
      static_cast<std::uint64_t>(inserted + 1), 0x31415926ULL,
      0x27182818ULL, "obf.bogus.pred.a", "obf.bogus.pred.b");
    if (predicate == nullptr) {
      sink->eraseFromParent();
      bogus->eraseFromParent();
      continue;
    }

    builder.CreateCondBr(predicate, successor, bogus);
    branch->eraseFromParent();
    populate_dse_trap(function, *bogus, *sink);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) + " bogus edge(s) inserted"};
}

} // namespace obf
