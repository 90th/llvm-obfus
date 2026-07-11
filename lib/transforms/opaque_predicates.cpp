#include "obf/transforms/opaque_predicates.h"

#include "obf/transforms/cfg_state_placeholders.h"
#include "obf/transforms/mba.h"
#include "obf/support/stable_hash.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ProfDataUtils.h"

#include <algorithm>
#include <cstdint>

namespace obf {

namespace {
enum class opaque_mux_shape : std::uint8_t { select, and_or };

struct opaque_site_decision {
  opaque_mux_shape shape;
  bool swap_successors;
  std::uint64_t salt_base;
};

opaque_site_decision choose_opaque_site(std::uint64_t function_seed, std::size_t site_index) {
  const bool odd_site = (site_index & 1U) != 0;
  const bool use_and_or = ((function_seed & 1U) != 0) ^ odd_site;
  const bool swap_successors = (((function_seed >> 1U) & 1U) != 0) ^ odd_site;
  return {.shape = use_and_or ? opaque_mux_shape::and_or : opaque_mux_shape::select,
          .swap_successors = swap_successors,
          .salt_base = mix_seed(function_seed, site_index + 1)};
}

void swap_branch_successors(llvm::BranchInst& branch) {
  const bool had_origin = llvm::hasBranchWeightOrigin(branch);
  llvm::SmallVector<std::uint32_t, 2> weights;
  const bool has_weights = llvm::extractBranchWeights(branch, weights) && weights.size() == 2;
  llvm::BasicBlock* first = branch.getSuccessor(0);
  llvm::BasicBlock* second = branch.getSuccessor(1);
  branch.setSuccessor(0, second);
  branch.setSuccessor(1, first);
  if (has_weights) {
    std::reverse(weights.begin(), weights.end());
    llvm::setBranchWeights(branch, weights, had_origin);
  }
}

opaque_predicate_result analyze_impl(const llvm::Function& function,
                                     const opaque_predicate_options& options) {
  if (function.isDeclaration()) { return {.insertion_count = 0, .detail = "declaration"}; }

  if (options.max_insertions_per_function == 0) {
    return {.insertion_count = 0, .detail = "max_insertions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    const auto* branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) { continue; }

    ++count;
    if (count >= options.max_insertions_per_function) {
      return {.insertion_count = count,
              .detail = std::to_string(count) + " opaque predicate site(s) available"};
    }
  }

  if (count == 0) { return {.insertion_count = 0, .detail = "no conditional branches"}; }

  return {.insertion_count = count,
          .detail = std::to_string(count) + " opaque predicate site(s) available"};
}

bool cleanup_cfg_state_placeholder(llvm::Module& module, llvm::StringRef name) {
  llvm::Function* placeholder = module.getFunction(name);
  if (placeholder == nullptr) { return false; }

  llvm::SmallVector<llvm::CallBase*, 8> calls;
  for (llvm::User* user : placeholder->users()) {
    if (auto* call = llvm::dyn_cast<llvm::CallBase>(user)) { calls.push_back(call); }
  }

  for (llvm::CallBase* call : calls) {
    if (call == nullptr) { continue; }

    call->replaceAllUsesWith(llvm::Constant::getNullValue(call->getType()));
    call->eraseFromParent();
  }

  const bool changed = !calls.empty();
  if (placeholder->use_empty() && placeholder->isDeclaration()) { placeholder->eraseFromParent(); }

  return changed;
}

}  // namespace

bool RunCfgStateCleanup(llvm::Module& module) {
  bool changed = false;
  changed |= cleanup_cfg_state_placeholder(module, kCfgStatePlaceholderName);
  changed |= cleanup_cfg_state_placeholder(module, kExpectedCfgStatePlaceholderName);
  return changed;
}

opaque_predicate_result analyze_opaque_predicates(const llvm::Function& function,
                                                  const opaque_predicate_options& options) {
  return analyze_impl(function, options);
}

opaque_predicate_result run_opaque_predicates(llvm::Function& function,
                                              const opaque_predicate_options& options) {
  const opaque_predicate_result analysis = analyze_impl(function, options);
  if (analysis.insertion_count == 0) { return analysis; }

  const std::uint64_t configured_seed =
      options.seed == 0 ? stable_hash_string("obf.opaque.default") : options.seed;
  const std::uint64_t function_seed =
      mix_seed(configured_seed, stable_hash_string(function.getName()));

  std::size_t inserted = 0;
  for (llvm::BasicBlock& block : function) {
    if (inserted >= options.max_insertions_per_function) { break; }

    auto* branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) { continue; }

    const opaque_site_decision site = choose_opaque_site(function_seed, inserted);
    llvm::IRBuilder<> builder(branch);
    llvm::Value* true_guard = mba::build_entropy_true_predicate(builder,
                                                                function,
                                                                options.mba_depth,
                                                                mix_seed(site.salt_base, 1),
                                                                0x13579bdfULL,
                                                                0x2468ace0ULL,
                                                                "obf.opaque.true.a",
                                                                "obf.opaque.true.b",
                                                                "obf.opaque.guard.true",
                                                                options.mba_max_ir_instructions,
                                                                options.mba_enable_polynomial,
                                                                options.mba_enable_multiplication);
    if (true_guard == nullptr) { continue; }

    llvm::Value* false_source =
        mba::build_entropy_true_predicate(builder,
                                          function,
                                          options.mba_depth,
                                          mix_seed(site.salt_base, 2),
                                          0x13579bdfULL,
                                          0x2468ace0ULL,
                                          "obf.opaque.false.a",
                                          "obf.opaque.false.b",
                                          "obf.opaque.guard.false.source",
                                          options.mba_max_ir_instructions,
                                          options.mba_enable_polynomial,
                                          options.mba_enable_multiplication);
    if (false_source == nullptr) { continue; }

    llvm::Value* false_guard = builder.CreateNot(false_source, "obf.opaque.guard.false");
    llvm::Value* condition = builder.CreateFreeze(branch->getCondition(), "obf.opaque.input");
    if (site.swap_successors) {
      condition = builder.CreateNot(condition, "obf.opaque.input.inverted");
      swap_branch_successors(*branch);
    }

    llvm::Value* new_condition = nullptr;
    if (site.shape == opaque_mux_shape::select) {
      new_condition =
          builder.CreateSelect(condition, true_guard, false_guard, "obf.opaque.mux.select");
    } else {
      llvm::Value* true_arm = builder.CreateAnd(condition, true_guard, "obf.opaque.mux.true");
      llvm::Value* inverted_condition = builder.CreateXor(condition, builder.getTrue());
      llvm::Value* false_arm =
          builder.CreateAnd(inverted_condition, false_guard, "obf.opaque.mux.false");
      new_condition = builder.CreateOr(true_arm, false_arm, "obf.opaque.mux.and_or");
    }

    branch->setCondition(new_condition);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) + " opaque predicate(s) inserted"};
}

}  // namespace obf
