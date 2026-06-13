#include "obf/vm/internal/virtualize_island_topology.h"
#include "obf/vm/internal/virtualize_anchor_scattering.h"
#include "obf/vm/virtualize_internal.h"

#include "obf/support/generated_names.h"

#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <algorithm>
#include <numeric>
#include <vector>

namespace obf::vm {


bool is_island_candidate_instruction(const micro_instruction& instruction) {
  switch (instruction.op) {
    case opcode::ret:
    case opcode::unreachable_op:
      return false;
    default:
      return true;
  }
}

void collect_reachable_island_blocks(llvm::BasicBlock* start,
                                     const rewrite_function_context& context,
                                     const llvm::DenseSet<llvm::BasicBlock*>& instruction_block_set,
                                     const llvm::DenseSet<llvm::BasicBlock*>& dispatch_block_set,
                                     llvm::SmallVectorImpl<llvm::BasicBlock*>& blocks) {
  llvm::DenseSet<llvm::BasicBlock*> seen;
  llvm::SmallVector<llvm::BasicBlock*, 16> worklist;
  worklist.push_back(start);

  while (!worklist.empty()) {
    llvm::BasicBlock* block = worklist.pop_back_val();
    if (block == nullptr || !seen.insert(block).second) { continue; }
    if (block == context.trap_block || dispatch_block_set.contains(block)) { continue; }
    if (block != start && instruction_block_set.contains(block)) { continue; }

    blocks.push_back(block);
    llvm::Instruction* terminator = block->getTerminator();
    if (terminator == nullptr || llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }
    for (llvm::BasicBlock* successor : llvm::successors(block)) { worklist.push_back(successor); }
  }
}

struct island_region_exits {
  llvm::SmallVector<llvm::BasicBlock*, 4> exits;
  bool exits_to_trap = false;
};

island_region_exits analyze_island_region_exits(llvm::ArrayRef<llvm::BasicBlock*> region_blocks,
                                                llvm::BasicBlock* trap_block) {
  island_region_exits result;
  llvm::DenseSet<llvm::BasicBlock*> region_set;
  for (llvm::BasicBlock* block : region_blocks) {
    region_set.insert(block);
    if (block == trap_block) { result.exits_to_trap = true; }
  }

  llvm::DenseSet<llvm::BasicBlock*> exit_set;
  for (llvm::BasicBlock* block : region_blocks) {
    llvm::Instruction* terminator = block->getTerminator();
    if (terminator == nullptr) { continue; }
    for (llvm::BasicBlock* successor : llvm::successors(block)) {
      if (region_set.contains(successor)) { continue; }
      if (successor == trap_block) { result.exits_to_trap = true; }
      if (exit_set.insert(successor).second) { result.exits.push_back(successor); }
    }
  }

  return result;
}

bool region_uses_blockaddress(llvm::ArrayRef<llvm::BasicBlock*> region_blocks) {
  for (llvm::BasicBlock* block : region_blocks) {
    for (llvm::Instruction& instruction : *block) {
      for (llvm::Use& operand : instruction.operands()) {
        if (llvm::isa<llvm::BlockAddress>(operand.get())) { return true; }
      }
    }
  }
  return false;
}

bool region_has_disallowed_control(llvm::ArrayRef<llvm::BasicBlock*> region_blocks) {
  for (llvm::BasicBlock* block : region_blocks) {
    if (block->isEHPad()) { return true; }
    for (llvm::Instruction& instruction : *block) {
      if (llvm::isa<llvm::AllocaInst,
                    llvm::IndirectBrInst,
                    llvm::InvokeInst,
                    llvm::CallBrInst,
                    llvm::CatchReturnInst,
                    llvm::CleanupReturnInst,
                    llvm::CatchSwitchInst,
                    llvm::ResumeInst>(instruction)) {
        return true;
      }
    }
  }
  return false;
}

bool is_safe_single_exit_island_region(
    llvm::ArrayRef<llvm::BasicBlock*> region_blocks,
    llvm::BasicBlock* entry,
    llvm::BasicBlock* trap_block,
    const llvm::DenseSet<llvm::BasicBlock*>& dispatch_block_set) {
  if (entry == nullptr || region_blocks.empty()) { return false; }

  llvm::DenseSet<llvm::BasicBlock*> region_set;
  for (llvm::BasicBlock* block : region_blocks) {
    if (block == nullptr || block == trap_block || dispatch_block_set.contains(block)) {
      return false;
    }
    region_set.insert(block);
  }
  if (!region_set.contains(entry)) { return false; }

  for (llvm::BasicBlock* block : region_blocks) {
    for (llvm::BasicBlock* predecessor : llvm::predecessors(block)) {
      if (!region_set.contains(predecessor) && block != entry) { return false; }
    }
  }

  const island_region_exits exits = analyze_island_region_exits(region_blocks, trap_block);
  if (exits.exits_to_trap || exits.exits.size() != 1 || exits.exits.front() == trap_block) {
    return false;
  }

  if (region_has_disallowed_control(region_blocks) || region_uses_blockaddress(region_blocks)) {
    return false;
  }

  return true;
}

llvm::BasicBlock* find_instruction_handler_entry(llvm::BasicBlock* instruction_block,
                                                 llvm::BasicBlock* trap_block) {
  if (instruction_block == nullptr) { return nullptr; }
  auto* branch = llvm::dyn_cast<llvm::BranchInst>(instruction_block->getTerminator());
  if (branch == nullptr || !branch->isConditional()) { return nullptr; }

  llvm::BasicBlock* successor0 = branch->getSuccessor(0);
  llvm::BasicBlock* successor1 = branch->getSuccessor(1);
  if (successor0 == trap_block && successor1 != trap_block) { return successor1; }
  if (successor1 == trap_block && successor0 != trap_block) { return successor0; }
  return nullptr;
}

std::string make_vm_island_helper_name(llvm::Module& module,
                                       const rewrite_function_context& context,
                                       std::uint64_t island_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_h", "", mix_seed(context.bytecode_seed, 0x151a0000ULL + island_index));
}

std::string make_vm_island_helper_name(llvm::Module& module,
                                       std::uint64_t bytecode_seed,
                                       std::uint64_t island_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_h", "", mix_seed(bytecode_seed, 0x151c0000ULL + island_index));
}

std::string make_vm_subisland_helper_name(llvm::Module& module,
                                          std::uint64_t bytecode_seed,
                                          std::uint64_t island_index,
                                          std::uint64_t subisland_index) {
  return obf::make_unique_obf_symbol_name(
      module,
      "__obf_vm_hs",
      "",
      mix_seed(bytecode_seed, 0x151e0000ULL + island_index * 0x100ULL + subisland_index));
}

std::string MakeVmIslandDecoyHelperName(llvm::Module& module,
                                        std::uint64_t bytecode_seed,
                                        std::uint64_t island_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_hd", "", mix_seed(bytecode_seed, 0x15200000ULL + island_index));
}

VmDecoyRoutePlan BuildVmDecoyRoutePlan(const bytecode_program& program,
                                       llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                                       llvm::ArrayRef<std::uint32_t> island_for_instruction,
                                       llvm::ArrayRef<std::size_t> owned_instructions,
                                       std::uint32_t real_instruction,
                                       std::uint32_t decoy_island,
                                       std::uint64_t salt) {
  VmDecoyRoutePlan plan;
  plan.real_instruction = real_instruction;
  plan.real_dispatch_index = dispatch_index_for_instruction[real_instruction];
  plan.real_island = island_for_instruction[real_instruction];
  plan.decoy_island = decoy_island;
  plan.salt = salt;
  if (owned_instructions.empty()) { return plan; }

  std::size_t decoy_position =
      static_cast<std::size_t>(mix_seed(salt, 0x15210000ULL) % owned_instructions.size());
  if (owned_instructions[decoy_position] == real_instruction && owned_instructions.size() > 1) {
    decoy_position = (decoy_position + 1) % owned_instructions.size();
  }

  plan.decoy_instruction = static_cast<std::uint32_t>(owned_instructions[decoy_position]);
  plan.decoy_dispatch_index = dispatch_index_for_instruction[plan.decoy_instruction];
  if (!program.argument_slots.empty()) {
    plan.decoy_slot = program.argument_slots[static_cast<std::size_t>(mix_seed(
        salt, 0x15210001ULL) % program.argument_slots.size())];
  } else if (!program.slots.empty()) {
    plan.decoy_slot = static_cast<std::uint32_t>(mix_seed(salt, 0x15210002ULL) % program.slots.size());
  }
  return plan;
}

bool should_use_state_islands(const bytecode_program& program,
                              vm_island_topology topology,
                              std::uint32_t island_count) {
  return topology == vm_island_topology::helper_shards && island_count >= 3 &&
         program.instructions.size() >= vm_island_min_instruction_count;
}

std::vector<std::uint32_t> assign_vm_instruction_islands(const bytecode_program& program,
                                                         std::uint64_t bytecode_seed,
                                                         std::uint32_t island_count) {
  std::vector<std::uint32_t> island_for_instruction(program.instructions.size(), 0);
  if (island_count == 0 || program.instructions.empty()) { return island_for_instruction; }

  std::vector<std::size_t> order(program.instructions.size());
  std::iota(order.begin(), order.end(), 0);
  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs, std::size_t rhs) {
    const std::uint64_t lhs_key = mix_seed(bytecode_seed, 0x151c1000ULL + lhs);
    const std::uint64_t rhs_key = mix_seed(bytecode_seed, 0x151c1000ULL + rhs);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  for (std::size_t position = 0; position < order.size(); ++position) {
    island_for_instruction[order[position]] = static_cast<std::uint32_t>(position % island_count);
  }
  return island_for_instruction;
}

std::uint32_t estimate_instruction_lowering_cost(const micro_instruction& instruction,
                                                 const bytecode_layout& layout) {
  std::uint32_t cost = 2U + static_cast<std::uint32_t>(instruction.operands.size()) +
                       static_cast<std::uint32_t>(layout.header_chunks.size()) +
                       static_cast<std::uint32_t>(layout.edge_target_offsets.size() * 2U);
  switch (instruction.op) {
    case opcode::load_int:
    case opcode::load_float:
    case opcode::load_ptr:
    case opcode::load_vector:
    case opcode::store_int:
    case opcode::store_float:
    case opcode::store_ptr:
    case opcode::store_vector:
    case opcode::gep:
    case opcode::gep_inbounds:
      cost += 5U;
      break;
    case opcode::memmove_fixed:
    case opcode::memcpy_fixed:
    case opcode::memset_fixed:
    case opcode::call:
      cost += 8U;
      break;
    case opcode::branch:
    case opcode::switch_op:
    case opcode::ret:
    case opcode::unreachable_op:
      cost += 6U + static_cast<std::uint32_t>(instruction.edges.size() * 4U) +
              static_cast<std::uint32_t>(instruction.case_values.size());
      break;
    default:
      cost += 3U;
      break;
  }
  return cost;
}

std::uint32_t opcode_family(opcode op) {
  switch (op) {
    case opcode::load_int:
    case opcode::load_float:
    case opcode::load_ptr:
    case opcode::load_vector:
    case opcode::store_int:
    case opcode::store_float:
    case opcode::store_ptr:
    case opcode::store_vector:
    case opcode::memmove_fixed:
    case opcode::memcpy_fixed:
    case opcode::memset_fixed:
      return 1;
    case opcode::call:
    case opcode::jump:
    case opcode::branch:
    case opcode::switch_op:
    case opcode::unreachable_op:
    case opcode::ret:
      return 2;
    case opcode::gep:
    case opcode::gep_inbounds:
    case opcode::ptr_to_int:
    case opcode::int_to_ptr:
    case opcode::bitcast:
    case opcode::addrspace_cast:
      return 3;
    default:
      return 0;
  }
}


llvm::SmallVector<std::size_t, 32>
collect_island_instruction_indices(const bytecode_program& program,
                                   llvm::ArrayRef<std::uint32_t> island_for_instruction,
                                   std::uint32_t island_index) {
  llvm::SmallVector<std::size_t, 32> owned;
  for (std::size_t instruction_index = 0; instruction_index < program.instructions.size();
       ++instruction_index) {
    if (island_for_instruction[instruction_index] == island_index) {
      owned.push_back(instruction_index);
    }
  }
  return owned;
}

subisland_plan build_subisland_plan(const bytecode_program& program,
                                    const serialized_bytecode_program& serialized,
                                    llvm::ArrayRef<std::size_t> owned_instructions,
                                    std::uint64_t bytecode_seed,
                                    std::uint32_t island_index) {
  subisland_plan plan;
  plan.subhelper_for_instruction.assign(program.instructions.size(), invalid_slot);
  if (owned_instructions.size() < vm_subisland_min_instruction_count) { return plan; }

  const std::uint64_t split_seed = mix_seed(bytecode_seed, 0x151e1000ULL + island_index);
  std::uint64_t total_cost = 0;
  for (std::size_t instruction_index : owned_instructions) {
    total_cost += estimate_instruction_lowering_cost(program.instructions[instruction_index],
                                                     serialized.layouts[instruction_index]);
  }

  const std::uint32_t seeded_target =
      static_cast<std::uint32_t>(vm_subisland_target_instruction_count + (split_seed % 5ULL));
  const std::uint32_t by_instruction_count =
      static_cast<std::uint32_t>((owned_instructions.size() + seeded_target - 1U) / seeded_target);
  const std::uint64_t cost_target = static_cast<std::uint64_t>(seeded_target) * 12ULL;
  const std::uint32_t by_cost =
      static_cast<std::uint32_t>((total_cost + cost_target - 1ULL) / cost_target);
  std::uint32_t subhelper_count =
      std::max<std::uint32_t>(2U, std::max(by_instruction_count, by_cost));
  if (subhelper_count > vm_subisland_max_count) {
    subhelper_count = static_cast<std::uint32_t>(vm_subisland_max_count);
    plan.capped = true;
  }
  if (subhelper_count < 2U) { return plan; }

  plan.instructions.resize(subhelper_count);
  plan.route_order.reserve(subhelper_count);
  for (std::uint32_t subhelper_index = 0; subhelper_index < subhelper_count; ++subhelper_index) {
    plan.route_order.push_back(subhelper_index);
  }
  std::stable_sort(
      plan.route_order.begin(), plan.route_order.end(), [&](std::uint32_t lhs, std::uint32_t rhs) {
        const std::uint64_t lhs_key = mix_seed(split_seed, 0x51570000ULL + lhs);
        const std::uint64_t rhs_key = mix_seed(split_seed, 0x51570000ULL + rhs);
        return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
      });

  llvm::SmallVector<std::size_t, 64> order(owned_instructions.begin(), owned_instructions.end());
  const bool family_biased = (split_seed & 1ULL) != 0;
  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs, std::size_t rhs) {
    const std::uint64_t lhs_key = mix_seed(split_seed, 0x51571000ULL + lhs);
    const std::uint64_t rhs_key = mix_seed(split_seed, 0x51571000ULL + rhs);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  llvm::SmallVector<std::uint64_t, 8> bucket_costs(subhelper_count, 0);
  for (std::size_t instruction_index : order) {
    const std::uint32_t cost = estimate_instruction_lowering_cost(
        program.instructions[instruction_index], serialized.layouts[instruction_index]);
    const std::uint32_t preferred =
        family_biased
            ? opcode_family(program.instructions[instruction_index].op) % subhelper_count
            : static_cast<std::uint32_t>(mix_seed(split_seed, instruction_index) % subhelper_count);
    std::uint32_t best = preferred;
    std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
    for (std::uint32_t offset = 0; offset < subhelper_count; ++offset) {
      const std::uint32_t candidate = (preferred + offset) % subhelper_count;
      const std::uint64_t candidate_cost = bucket_costs[candidate];
      if (candidate_cost < best_cost) {
        best = candidate;
        best_cost = candidate_cost;
      }
    }
    plan.subhelper_for_instruction[instruction_index] = best;
    plan.instructions[best].push_back(instruction_index);
    bucket_costs[best] += cost;
  }

  plan.instructions.erase(std::remove_if(plan.instructions.begin(),
                                         plan.instructions.end(),
                                         [](const llvm::SmallVector<std::size_t, 16>& indices) {
                                           return indices.empty();
                                         }),
                          plan.instructions.end());
  if (plan.instructions.size() < 2) {
    plan.instructions.clear();
    plan.route_order.clear();
    std::fill(
        plan.subhelper_for_instruction.begin(), plan.subhelper_for_instruction.end(), invalid_slot);
    return plan;
  }

  std::fill(
      plan.subhelper_for_instruction.begin(), plan.subhelper_for_instruction.end(), invalid_slot);
  plan.route_order.clear();
  for (std::uint32_t subhelper_index = 0; subhelper_index < plan.instructions.size();
       ++subhelper_index) {
    plan.route_order.push_back(subhelper_index);
    for (std::size_t instruction_index : plan.instructions[subhelper_index]) {
      plan.subhelper_for_instruction[instruction_index] = subhelper_index;
    }
  }
  std::stable_sort(
      plan.route_order.begin(), plan.route_order.end(), [&](std::uint32_t lhs, std::uint32_t rhs) {
        const std::uint64_t lhs_key = mix_seed(split_seed, 0x51572000ULL + lhs);
        const std::uint64_t rhs_key = mix_seed(split_seed, 0x51572000ULL + rhs);
        return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
      });

  return plan;
}


std::uint32_t outline_vm_islands(rewrite_function_context& context) {
  if (context.island_topology != vm_island_topology::helper_shards || context.island_count < 2 ||
      context.dispatch_backend != dispatch_backend_variant::switch_index ||
      context.switch_dispatch_banks.size() != 1 || context.instruction_blocks.empty()) {
    return 0;
  }

  const switch_dispatch_bank& bank = context.switch_dispatch_banks.front();
  if (bank.switch_inst == nullptr || bank.dispatch_index_phi == nullptr) { return 0; }

  llvm::DenseSet<llvm::BasicBlock*> instruction_block_set;
  for (llvm::BasicBlock* block : context.instruction_blocks) {
    instruction_block_set.insert(block);
  }
  llvm::DenseSet<llvm::BasicBlock*> dispatch_block_set;
  for (const switch_dispatch_bank& dispatch_bank : context.switch_dispatch_banks) {
    dispatch_block_set.insert(dispatch_bank.block);
  }

  struct island_assignment {
    std::size_t instruction_index = 0;
    std::uint32_t island_index = 0;
    std::uint64_t rank = 0;
  };

  llvm::SmallVector<island_assignment, 64> assignments;
  for (std::size_t instruction_index = 0; instruction_index < context.program.instructions.size();
       ++instruction_index) {
    if (!is_island_candidate_instruction(context.program.instructions[instruction_index])) {
      continue;
    }
    const std::uint64_t rank = mix_seed(context.bytecode_seed, 0x151a1000ULL + instruction_index);
    assignments.push_back({.instruction_index = instruction_index,
                           .island_index = static_cast<std::uint32_t>(rank % context.island_count),
                           .rank = rank});
  }
  if (assignments.size() < context.island_count * 2U) { return 0; }

  std::stable_sort(assignments.begin(),
                   assignments.end(),
                   [](const island_assignment& lhs, const island_assignment& rhs) {
                     return lhs.rank == rhs.rank ? lhs.instruction_index < rhs.instruction_index
                                                 : lhs.rank < rhs.rank;
                   });

  llvm::CodeExtractorAnalysisCache cache(context.function);
  llvm::DominatorTree dom_tree(context.function);
  llvm::LoopInfo loop_info(dom_tree);
  llvm::AssumptionCache assumption_cache(context.function);
  (void)loop_info;

  std::uint32_t extracted_count = 0;
  for (std::uint32_t island_index = 0; island_index < context.island_count; ++island_index) {
    llvm::SmallVector<std::size_t, 16> island_instructions;
    for (const island_assignment& assignment : assignments) {
      if (assignment.island_index == island_index) {
        island_instructions.push_back(assignment.instruction_index);
      }
    }
    if (island_instructions.size() < 2) { continue; }

    for (std::size_t instruction_index : island_instructions) {
      llvm::BasicBlock* handler_entry = find_instruction_handler_entry(
          context.instruction_blocks[instruction_index], context.trap_block);
      if (handler_entry == nullptr) { continue; }

      llvm::SmallVector<llvm::BasicBlock*, 32> region_blocks;
      collect_reachable_island_blocks(
          handler_entry, context, instruction_block_set, dispatch_block_set, region_blocks);

      llvm::DenseSet<llvm::BasicBlock*> unique_region_blocks;
      llvm::SmallVector<llvm::BasicBlock*, 32> deduped_region_blocks;
      for (llvm::BasicBlock* block : region_blocks) {
        if (unique_region_blocks.insert(block).second) { deduped_region_blocks.push_back(block); }
      }

      if (!is_safe_single_exit_island_region(
              deduped_region_blocks, handler_entry, context.trap_block, dispatch_block_set)) {
        continue;
      }

      dom_tree.recalculate(context.function);
      llvm::CodeExtractor extractor(
          deduped_region_blocks,
          &dom_tree,
          /*aggregate args=*/true,
          /*bfi=*/nullptr,
          /*bpi=*/nullptr,
          &assumption_cache,
          /*allow var args=*/false,
          /*allow alloca=*/false,
          /*allocation block=*/nullptr,
          make_vm_island_helper_name(*context.function.getParent(), context, island_index));
      if (!extractor.isEligible()) {
        dom_tree.recalculate(context.function);
        continue;
      }

      llvm::Function* helper = extractor.extractCodeRegion(cache);
      if (helper == nullptr) {
        dom_tree.recalculate(context.function);
        continue;
      }

      helper->setName(make_vm_island_helper_name(
          *context.function.getParent(), context, 0x100ULL + island_index));
      helper->setLinkage(llvm::GlobalValue::InternalLinkage);
      helper->setDSOLocal(true);
      helper->addFnAttr("vm.island.helper");
      ++extracted_count;
      dom_tree.recalculate(context.function);
      break;
    }
  }

  if (extracted_count > 0) {
    context.function.addFnAttr("vm.island.entry");
    context.function.addFnAttr("vm.island.topology.helper_shards");
    context.function.addFnAttr("vm.island.count." + std::to_string(extracted_count));
  }

  return extracted_count;
}

}  // namespace obf::vm
