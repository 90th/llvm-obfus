#include "obf/transforms/bogus_control_flow.h"

#include "obf/support/decoy_trap.h"
#include "obf/support/stable_hash.h"
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

bool is_supported_branch_candidate(llvm::BasicBlock& block) {
  auto* branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
  if (branch == nullptr || !branch->isUnconditional()) { return false; }

  llvm::BasicBlock* successor = branch->getSuccessor(0);
  return successor != nullptr && successor->phis().empty();
}

void populate_dse_trap(llvm::Function& function, llvm::BasicBlock& bogus, llvm::BasicBlock& sink,
                       std::uint64_t site_seed) {
  llvm::LLVMContext& context = function.getContext();

  if (((site_seed >> 1) & 1ULL) == 0ULL) {
    // Family 0: entropy-seeded decoy loop.
    llvm::BasicBlock* loop = llvm::BasicBlock::Create(context, "obf.bogus.loop", &function, &sink);

    llvm::IRBuilder<> bogus_builder(&bogus);
    llvm::Value* initial_entropy =
        bogus_builder.CreateLoad(bogus_builder.getInt64Ty(),
                                 mba::get_or_create_entropy_anchor(*function.getParent()),
                                 "obf.bogus.seed");
    llvm::Value* initial_state = bogus_builder.CreateXor(
        initial_entropy,
        llvm::ConstantInt::get(bogus_builder.getInt64Ty(), mix_seed(site_seed, 0x1ULL)),
        "obf.bogus.state.init");
    bogus_builder.CreateBr(loop);

    llvm::IRBuilder<> loop_builder(loop);
    llvm::PHINode* iteration = loop_builder.CreatePHI(loop_builder.getInt32Ty(), 2, "obf.bogus.iter");
    llvm::PHINode* state = loop_builder.CreatePHI(loop_builder.getInt64Ty(), 2, "obf.bogus.state");
    auto loop_state = support::build_decoy_loop_core(loop_builder, state, iteration, "obf.bogus");
    const std::uint32_t trip_count = 900000U + static_cast<std::uint32_t>(site_seed % 200001ULL);
    llvm::Value* done = loop_builder.CreateICmpEQ(
        loop_state.next_iteration,
        llvm::ConstantInt::get(loop_builder.getInt32Ty(), trip_count),
        "obf.bogus.done");
    loop_builder.CreateCondBr(done, &sink, loop);

    iteration->addIncoming(llvm::ConstantInt::get(loop_builder.getInt32Ty(), 0), &bogus);
    iteration->addIncoming(loop_state.next_iteration, loop);
    state->addIncoming(initial_state, &bogus);
    state->addIncoming(loop_state.next_state, loop);
  } else {
    // Family 1: straight-line entropy-seeded arithmetic decoy (no loop).
    llvm::IRBuilder<> bogus_builder(&bogus);
    llvm::Type* word_type = bogus_builder.getInt64Ty();
    llvm::Value* seed_value =
        bogus_builder.CreateLoad(word_type,
                                 mba::get_or_create_entropy_anchor(*function.getParent()),
                                 "obf.bogus.seed");
    llvm::Value* acc0 = bogus_builder.CreateXor(
        seed_value, llvm::ConstantInt::get(word_type, mix_seed(site_seed, 0x2ULL)), "obf.bogus.acc0");
    llvm::Value* product = bogus_builder.CreateMul(
        acc0, llvm::ConstantInt::get(word_type, mix_seed(site_seed, 0x3ULL) | 1ULL),
        "obf.bogus.acc1.mul");
    llvm::Value* acc1 = bogus_builder.CreateAdd(
        product, llvm::ConstantInt::get(word_type, mix_seed(site_seed, 0x4ULL)), "obf.bogus.acc1");
    llvm::Value* acc2 = bogus_builder.CreateXor(
        acc1, llvm::ConstantInt::get(word_type, mix_seed(site_seed, 0x5ULL)), "obf.bogus.acc2");
    (void)acc2;
    bogus_builder.CreateBr(&sink);
  }

  llvm::IRBuilder<> sink_builder(&sink);
  sink_builder.CreateBr(sink.getNextNode());
}

bogus_control_flow_result analyze_impl(const llvm::Function& function,
                                       const bogus_control_flow_options& options) {
  if (function.isDeclaration()) { return {.insertion_count = 0, .detail = "declaration"}; }

  if (options.max_insertions_per_function == 0) {
    return {.insertion_count = 0, .detail = "max_insertions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    if (const_cast<llvm::BasicBlock&>(block).phis().empty() &&
        const_cast<llvm::BasicBlock&>(block).getTerminator() != nullptr) {
      if (const_cast<llvm::BasicBlock&>(block).isEHPad()) { continue; }
      if (const auto* branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator())) {
        if (branch->isUnconditional() && branch->getSuccessor(0)->phis().empty()) {
          ++count;
          if (count >= options.max_insertions_per_function) {
            return {.insertion_count = count,
                    .detail = std::to_string(count) + " bogus edge(s) available"};
          }
        }
      }
    }
  }

  if (count == 0) {
    return {.insertion_count = 0, .detail = "no unconditional branches with phi-free successors"};
  }

  return {.insertion_count = count, .detail = std::to_string(count) + " bogus edge(s) available"};
}

}  // namespace

bogus_control_flow_result analyze_bogus_control_flow(const llvm::Function& function,
                                                     const bogus_control_flow_options& options) {
  return analyze_impl(function, options);
}

bogus_control_flow_result run_bogus_control_flow(llvm::Function& function,
                                                 const bogus_control_flow_options& options) {
  const bogus_control_flow_result analysis = analyze_impl(function, options);
  if (analysis.insertion_count == 0) { return analysis; }

  std::size_t inserted = 0;
  const std::uint64_t function_seed =
      mix_seed(options.seed, stable_hash_string(function.getName()));
  llvm::SmallVector<llvm::BasicBlock*, 16> blocks;
  for (llvm::BasicBlock& block : function) { blocks.push_back(&block); }

  for (llvm::BasicBlock* block : blocks) {
    if (inserted >= options.max_insertions_per_function || block == nullptr ||
        !is_supported_branch_candidate(*block)) {
      continue;
    }

    auto* branch = llvm::cast<llvm::BranchInst>(block->getTerminator());
    llvm::BasicBlock* successor = branch->getSuccessor(0);
    llvm::BasicBlock* bogus =
        llvm::BasicBlock::Create(function.getContext(), "obf.bogus", &function, successor);
    llvm::BasicBlock* sink =
        llvm::BasicBlock::Create(function.getContext(), "obf.bogus.sink", &function, successor);

    llvm::IRBuilder<> builder(branch);
    const std::uint64_t site_seed =
        mix_seed(function_seed, static_cast<std::uint64_t>(inserted + 1));
    llvm::Value* predicate =
        mba::build_entropy_true_predicate(builder,
                                          function,
                                          options.mba_depth,
                                          site_seed,
                                          site_seed,
                                          site_seed,
                                          "obf.bogus.pred.a",
                                          "obf.bogus.pred.b",
                                          "obf.bogus.true",
                                          options.mba_max_ir_instructions,
                                          options.mba_enable_polynomial,
                                          options.mba_enable_multiplication);
    if (predicate == nullptr) {
      sink->eraseFromParent();
      bogus->eraseFromParent();
      continue;
    }

    if ((site_seed & 1ULL) == 0ULL) {
      builder.CreateCondBr(predicate, successor, bogus);
    } else {
      builder.CreateCondBr(builder.CreateNot(predicate, "obf.bogus.false"), bogus, successor);
    }
    branch->eraseFromParent();
    populate_dse_trap(function, *bogus, *sink, site_seed);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) + " bogus edge(s) inserted"};
}

}  // namespace obf
