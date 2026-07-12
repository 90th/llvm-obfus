#include "obf/plugin/internal/plugin_vm_target_discovery.h"
#include "obf/plugin/internal/plugin_vm_binding_prep.h"

#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/support/generated_names.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <string>

namespace obf {

namespace {

struct vm_region_candidate {
  llvm::BasicBlock* header = nullptr;
  llvm::SmallVector<llvm::BasicBlock*, 8> region_blocks;
  std::size_t score = 0;
};

std::string build_vm_region_helper_name(llvm::Function& function,
                                        std::uint64_t ordinal,
                                        std::uint64_t seed,
                                        bool preserve_generated_names) {
  if (preserve_generated_names) {
    return llvm::formatv("__obf_vm_region_{0}_{1:x}", function.getName(), ordinal + 1).str();
  }

  llvm::Module* module = function.getParent();
  if (module == nullptr) {
    return make_obf_symbol_name(
        "__obf_vm_g", function.getName(), mix_generated_name_seed(seed, ordinal + 1));
  }

  return make_unique_obf_symbol_name(
      *module, "__obf_vm_g", function.getName(), mix_generated_name_seed(seed, ordinal + 1));
}

bool region_contains_vararg_intrinsic(llvm::ArrayRef<llvm::BasicBlock*> region_blocks) {
  for (llvm::BasicBlock* region_block : region_blocks) {
    if (region_block == nullptr) { continue; }

    for (const llvm::Instruction& instruction : *region_block) {
      if (llvm::isa<llvm::VAArgInst>(instruction)) { return true; }

      const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&instruction);
      if (intrinsic == nullptr) { continue; }
      switch (intrinsic->getIntrinsicID()) {
        case llvm::Intrinsic::vastart:
        case llvm::Intrinsic::vaend:
        case llvm::Intrinsic::vacopy:
          return true;
        default:
          break;
      }
    }
  }

  return false;
}

void append_vm_region_candidate(llvm::Function& function,
                                llvm::BasicBlock* header,
                                llvm::ArrayRef<llvm::BasicBlock*> region_blocks,
                                llvm::SmallVectorImpl<vm_region_candidate>& candidates) {
  if (header == nullptr || region_contains_vararg_intrinsic(region_blocks)) { return; }

  llvm::CodeExtractorAnalysisCache cache(function);
  llvm::DominatorTree dom_tree(function);
  llvm::AssumptionCache assumption_cache(function);
  llvm::CodeExtractor extractor(region_blocks,
                                &dom_tree,
                                /*AggregateArgs=*/false,
                                /*BFI=*/nullptr,
                                /*BPI=*/nullptr,
                                &assumption_cache,
                                /*AllowVarArgs=*/false,
                                /*AllowAlloca=*/false,
                                /*AllocationBlock=*/nullptr,
                                "obf.vm.region.check");
  if (!extractor.isEligible()) { return; }

  std::size_t instruction_count = 0;
  for (llvm::BasicBlock* region_block : region_blocks) {
    instruction_count += region_block->size();
  }

  llvm::SmallVector<llvm::BasicBlock*, 8> stored_blocks(region_blocks.begin(),
                                                        region_blocks.end());
  candidates.push_back(vm_region_candidate{.header = header,
                                           .region_blocks = std::move(stored_blocks),
                                           .score = instruction_count});
}

void collect_loop_region_candidates(llvm::Function& function,
                                    llvm::Loop& loop,
                                    llvm::SmallVectorImpl<vm_region_candidate>& candidates) {
  if (!loop.isInnermost()) {
    for (llvm::Loop* subloop : loop) {
      if (subloop != nullptr) { collect_loop_region_candidates(function, *subloop, candidates); }
    }
    return;
  }

  llvm::SmallVector<llvm::BasicBlock*, 8> region_blocks;
  for (llvm::BasicBlock* block : loop.blocks()) {
    if (block != nullptr) { region_blocks.push_back(block); }
  }

  if (region_blocks.empty()) { return; }
  append_vm_region_candidate(function, loop.getHeader(), region_blocks, candidates);
}

llvm::SmallVector<vm_region_candidate, 8>
find_regional_vm_candidates(llvm::Function& function, const llvm::StringSet<>& skip_functions) {
  llvm::SmallVector<vm_region_candidate, 8> candidates;
  if (skip_functions.contains(function.getName())) { return candidates; }

  llvm::DominatorTree dom_tree(function);
  llvm::LoopInfo loop_info(dom_tree);

  for (llvm::BasicBlock& block : function) {
    if (block.getName().starts_with("entry.obf.vm") ||
        block.getName().starts_with("trap.obf.vm") || block.getName().starts_with("vm.")) {
      continue;
    }

    auto* branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) { continue; }

    llvm::SmallVector<llvm::BasicBlock*, 8> region_blocks;
    llvm::BasicBlock* true_block = branch->getSuccessor(0);
    llvm::BasicBlock* false_block = branch->getSuccessor(1);
    if (true_block != false_block && llvm::pred_size(true_block) == 1 &&
        llvm::pred_size(false_block) == 1) {
      auto* true_term = llvm::dyn_cast<llvm::BranchInst>(true_block->getTerminator());
      auto* false_term = llvm::dyn_cast<llvm::BranchInst>(false_block->getTerminator());
      if (true_term != nullptr && false_term != nullptr && true_term->isUnconditional() &&
          false_term->isUnconditional() &&
          true_term->getSuccessor(0) == false_term->getSuccessor(0)) {
        llvm::BasicBlock* merge_block = true_term->getSuccessor(0);
        if (merge_block != &block && merge_block != true_block && merge_block != false_block &&
            llvm::pred_size(merge_block) == 2) {
          region_blocks = {&block, true_block, false_block};
          append_vm_region_candidate(function, &block, region_blocks, candidates);
        }
      }
    }

    for (llvm::BasicBlock* successor : branch->successors()) {
      if (successor == nullptr || successor == &block || llvm::pred_size(successor) != 1) {
        continue;
      }

      auto* succ_term = llvm::dyn_cast<llvm::BranchInst>(successor->getTerminator());
      if (succ_term != nullptr && succ_term->isUnconditional()) {
        region_blocks = {&block, successor};
        append_vm_region_candidate(function, &block, region_blocks, candidates);
      }
    }
  }

  for (llvm::Loop* loop : loop_info) {
    if (loop != nullptr) { collect_loop_region_candidates(function, *loop, candidates); }
  }

  llvm::sort(candidates, [](const vm_region_candidate& lhs, const vm_region_candidate& rhs) {
    if (lhs.score != rhs.score) { return lhs.score > rhs.score; }
    return lhs.header->getName() < rhs.header->getName();
  });
  return candidates;
}

bool can_virtualize_extracted_region(llvm::Function& function,
                                     const vm_region_candidate& candidate,
                                     std::uint64_t helper_ordinal,
                                     std::uint64_t seed,
                                     bool preserve_generated_names) {
  llvm::ValueToValueMapTy value_map;
  llvm::Function* clone = llvm::CloneFunction(&function, value_map);
  if (clone == nullptr) { return false; }

  clone->setName(
      build_vm_region_helper_name(function, helper_ordinal, seed, preserve_generated_names) +
      ".probe");
  llvm::BasicBlock* clone_header = llvm::cast<llvm::BasicBlock>(value_map.lookup(candidate.header));
  llvm::SmallVector<llvm::BasicBlock*, 8> region_blocks;
  region_blocks.reserve(candidate.region_blocks.size());
  region_blocks.push_back(clone_header);
  for (std::size_t region_index = 1; region_index < candidate.region_blocks.size();
       ++region_index) {
    llvm::BasicBlock* region_block = candidate.region_blocks[region_index];
    region_blocks.push_back(llvm::cast<llvm::BasicBlock>(value_map.lookup(region_block)));
  }

  llvm::CodeExtractorAnalysisCache cache(*clone);
  llvm::DominatorTree dom_tree(*clone);
  llvm::AssumptionCache assumption_cache(*clone);
  llvm::CodeExtractor extractor(region_blocks,
                                &dom_tree,
                                /*AggregateArgs=*/false,
                                /*BFI=*/nullptr,
                                /*BPI=*/nullptr,
                                &assumption_cache,
                                /*AllowVarArgs=*/false,
                                /*AllowAlloca=*/false,
                                /*AllocationBlock=*/nullptr,
                                "obf.vm.region.probe");
  if (!extractor.isEligible()) {
    clone->eraseFromParent();
    return false;
  }

  llvm::SetVector<llvm::Value*> inputs;
  llvm::SetVector<llvm::Value*> outputs;
  llvm::Function* extracted = extractor.extractCodeRegion(cache, inputs, outputs);
  bool eligible = extracted != nullptr && vm::analyze_candidate(*extracted).eligible &&
                  analyze_vm_boundary(*extracted, {}).target_supported;
  if (extracted != nullptr) { extracted->eraseFromParent(); }
  clone->eraseFromParent();
  return eligible;
}

llvm::Function* extract_regional_vm_helper(llvm::Function& function,
                                           const vm_region_candidate& candidate,
                                           std::uint64_t helper_ordinal,
                                           std::uint64_t seed,
                                           bool preserve_generated_names) {
  llvm::SmallVector<llvm::BasicBlock*, 8> region_blocks(candidate.region_blocks.begin(),
                                                        candidate.region_blocks.end());
  llvm::CodeExtractorAnalysisCache cache(function);
  llvm::DominatorTree dom_tree(function);
  llvm::AssumptionCache assumption_cache(function);
  llvm::CodeExtractor extractor(
      region_blocks,
      &dom_tree,
      /*AggregateArgs=*/false,
      /*BFI=*/nullptr,
      /*BPI=*/nullptr,
      &assumption_cache,
      /*AllowVarArgs=*/false,
      /*AllowAlloca=*/false,
      /*AllocationBlock=*/nullptr,
      build_vm_region_helper_name(function, helper_ordinal, seed, preserve_generated_names));
  if (!extractor.isEligible()) { return nullptr; }

  llvm::Function* helper = extractor.extractCodeRegion(cache);
  if (helper == nullptr) { return nullptr; }

  helper->setName(build_vm_region_helper_name(function, helper_ordinal, seed, preserve_generated_names));
  helper->setLinkage(llvm::GlobalValue::InternalLinkage);
  helper->setDSOLocal(true);
  return helper;
}

bool collect_regional_vm_targets(llvm::Function& function,
                                 const function_pipeline_state& state,
                                 llvm::StringSet<>& skip_functions,
                                 std::uint64_t& helper_ordinal,
                                 std::size_t nesting_depth,
                                 std::size_t max_nesting_depth,
                                 std::size_t max_regions,
                                 bool preserve_generated_names,
                                 llvm::SmallVectorImpl<vm_target_candidate>& targets) {
  bool extracted_any = false;
  std::size_t extracted_count = 0;
  while (extracted_count < max_regions) {
    const llvm::SmallVector<vm_region_candidate, 8> candidates =
        find_regional_vm_candidates(function, skip_functions);
    bool extracted_this_round = false;
    for (const vm_region_candidate& candidate : candidates) {
      if (!can_virtualize_extracted_region(function,
                                           candidate,
                                           helper_ordinal,
                                           state.report.decision.seed,
                                           preserve_generated_names)) {
        continue;
      }

      llvm::Function* helper = extract_regional_vm_helper(function,
                                                          candidate,
                                                          helper_ordinal++,
                                                          state.report.decision.seed,
                                                          preserve_generated_names);
      if (helper == nullptr) { continue; }

      llvm::SmallVector<vm_target_candidate, 4> nested_targets;
      if (nesting_depth < max_nesting_depth) {
        (void)collect_regional_vm_targets(*helper,
                                          state,
                                          skip_functions,
                                          helper_ordinal,
                                          nesting_depth + 1,
                                          max_nesting_depth,
                                          /*max_regions=*/1,
                                          preserve_generated_names,
                                          nested_targets);
      }

      if (vm::analyze_candidate(*helper).eligible) {
        targets.push_back(
            {.function = helper, .state = &state, .nesting_depth = nesting_depth + 1});
      }
      for (const vm_target_candidate& nested_target : nested_targets) {
        targets.push_back(nested_target);
      }

      extracted_any = true;
      extracted_this_round = true;
      ++extracted_count;
      break;
    }

    if (!extracted_this_round) { break; }
  }

  return extracted_any;
}

}  // namespace

llvm::SmallVector<vm_target_candidate, 8>
discover_vm_targets_for_state(const function_pipeline_state& state,
                              llvm::StringSet<>& skip_functions,
                              std::uint64_t& helper_ordinal,
                              bool preserve_generated_names) {
  llvm::SmallVector<vm_target_candidate, 8> targets;
  if (state.function == nullptr || state.function->isDeclaration() ||
      skip_functions.contains(state.function->getName())) {
    return targets;
  }

  if (state.function->isVarArg()) { return targets; }

  const vm::candidate_result whole_function_analysis = vm::analyze_candidate(*state.function);

  if (state.report.decision.policy.level == protection_level::strong_vm) {
    if (whole_function_analysis.eligible) {
      targets.push_back({.function = state.function, .state = &state, .nesting_depth = 0});
      return targets;
    }

    const bool extracted_regions = collect_regional_vm_targets(*state.function,
                                                               state,
                                                               skip_functions,
                                                               helper_ordinal,
                                                               /*nesting_depth=*/0,
                                                               /*max_nesting_depth=*/1,
                                                               /*max_regions=*/2,
                                                               preserve_generated_names,
                                                               targets);
    if (extracted_regions) { return targets; }
  }

  if (whole_function_analysis.eligible) {
    targets.push_back({.function = state.function, .state = &state, .nesting_depth = 0});
  }
  return targets;
}

}  // namespace obf
