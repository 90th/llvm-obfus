#include "obf/vm/virtualize_internal.h"

#include "obf/support/generated_names.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <numeric>
#include <string>
#include <vector>

namespace obf::vm {

namespace {

bool should_preserve_function_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute()) {
    return true;
  }

  if (!attribute.hasKindAsEnum()) {
    return false;
  }

  if (llvm::Attribute::intersectMustPreserve(attribute.getKindAsEnum())) {
    return true;
  }

  switch (attribute.getKindAsEnum()) {
  case llvm::Attribute::AlwaysInline:
  case llvm::Attribute::Cold:
  case llvm::Attribute::Convergent:
  case llvm::Attribute::DisableSanitizerInstrumentation:
  case llvm::Attribute::Hot:
  case llvm::Attribute::InlineHint:
  case llvm::Attribute::JumpTable:
  case llvm::Attribute::MinSize:
  case llvm::Attribute::MustProgress:
  case llvm::Attribute::NoFree:
  case llvm::Attribute::NoInline:
  case llvm::Attribute::NoRedZone:
  case llvm::Attribute::NoSync:
  case llvm::Attribute::NoUnwind:
  case llvm::Attribute::NullPointerIsValid:
  case llvm::Attribute::OptimizeForDebugging:
  case llvm::Attribute::OptimizeForSize:
  case llvm::Attribute::OptimizeNone:
  case llvm::Attribute::SafeStack:
  case llvm::Attribute::SanitizeAddress:
  case llvm::Attribute::SanitizeHWAddress:
  case llvm::Attribute::SanitizeMemTag:
  case llvm::Attribute::SanitizeMemory:
  case llvm::Attribute::SanitizeNumericalStability:
  case llvm::Attribute::SanitizeRealtime:
  case llvm::Attribute::SanitizeRealtimeBlocking:
  case llvm::Attribute::SanitizeThread:
  case llvm::Attribute::SanitizeType:
  case llvm::Attribute::ShadowCallStack:
  case llvm::Attribute::SpeculativeLoadHardening:
  case llvm::Attribute::StackProtect:
  case llvm::Attribute::StackProtectReq:
  case llvm::Attribute::StackProtectStrong:
  case llvm::Attribute::StrictFP:
  case llvm::Attribute::UWTable:
  case llvm::Attribute::WillReturn:
    return true;
  default:
    return false;
  }
}

llvm::AttributeList build_preserved_function_attributes(llvm::Function &function) {
  llvm::LLVMContext &context = function.getContext();
  const llvm::AttributeList original = function.getAttributes();
  llvm::AttributeList preserved;

  for (llvm::Attribute attribute : original.getRetAttrs()) {
    preserved = preserved.addRetAttribute(context, attribute);
  }

  for (llvm::Argument &argument : function.args()) {
    const unsigned argument_index = argument.getArgNo();
    for (llvm::Attribute attribute : original.getParamAttrs(argument_index)) {
      preserved = preserved.addAttributeAtIndex(
          context, llvm::AttributeList::FirstArgIndex + argument_index, attribute);
    }
  }

  for (llvm::Attribute attribute : original.getFnAttrs()) {
    if (should_preserve_function_attribute(attribute)) {
      if (attribute.isStringAttribute()) {
        preserved = preserved.addFnAttribute(context, attribute.getKindAsString(),
                                             attribute.getValueAsString());
        continue;
      }

      preserved = preserved.addFnAttribute(context, attribute);
    }
  }

  return preserved;
}

std::uint64_t derive_vm_opaque_seed(const llvm::Function &function,
                                    const bytecode_program &program) {
  std::uint64_t seed =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName()));
  seed ^= static_cast<std::uint64_t>(program.instructions.size()) *
          0x9e3779b97f4a7c15ULL;
  seed ^= static_cast<std::uint64_t>(program.slots.size()) << 32;
  if (seed == 0) {
    seed = 0x6a09e667f3bcc909ULL;
  }

  return seed;
}

std::uint64_t derive_vm_return_key(const llvm::Function &function,
                                   const bytecode_program &program) {
  return mix_seed(derive_vm_opaque_seed(function, program),
                  0xdeadbeefcafebabeULL);
}

llvm::Value *build_hidden_token_seed(llvm::IRBuilder<> &builder,
                                     llvm::Argument *hidden_token_arg,
                                     std::uint64_t canonical_seed,
                                     llvm::ArrayRef<std::uint64_t> valid_tokens,
                                     const mba::builder_context &mba_context,
                                     std::uint64_t salt,
                                     llvm::StringRef name) {
  if (hidden_token_arg == nullptr) {
    return builder.getInt64(canonical_seed);
  }

  llvm::Value *hidden_token = hidden_token_arg;
  if (hidden_token->getType() != builder.getInt64Ty()) {
    hidden_token = builder.CreateZExtOrTrunc(hidden_token, builder.getInt64Ty(),
                                             "obf.vm.token.cast");
  }

  llvm::Value *selected = mba::entangle_value(
      builder, hidden_token, mba_context, salt ^ 0xabcddcbaULL,
      (name + ".fallback").str());
  for (std::size_t token_index = 0; token_index < valid_tokens.size(); ++token_index) {
    llvm::Value *token_const = mba::create_opaque_integer(
        builder, builder.getInt64Ty(), mba_context,
        llvm::APInt(64, valid_tokens[token_index]),
        salt + static_cast<std::uint64_t>(token_index) * 8 + 1,
        (name + ".token").str());
    llvm::Value *seed_const = mba::create_opaque_integer(
        builder, builder.getInt64Ty(), mba_context,
        llvm::APInt(64, canonical_seed),
        salt + static_cast<std::uint64_t>(token_index) * 8 + 2,
        (name + ".seed").str());
    llvm::Value *match = builder.CreateICmpEQ(hidden_token, token_const,
                                              (name + ".match").str());
    selected = builder.CreateSelect(match, seed_const, selected,
                                    name.empty() ? "obf.vm.token.seed" : name);
  }

  return selected;
}

bool is_island_candidate_instruction(const micro_instruction &instruction) {
  switch (instruction.op) {
  case opcode::ret:
  case opcode::unreachable_op:
    return false;
  default:
    return true;
  }
}

void collect_reachable_island_blocks(
    llvm::BasicBlock *start, const rewrite_function_context &context,
    const llvm::DenseSet<llvm::BasicBlock *> &instruction_block_set,
    const llvm::DenseSet<llvm::BasicBlock *> &dispatch_block_set,
    llvm::SmallVectorImpl<llvm::BasicBlock *> &blocks) {
  llvm::DenseSet<llvm::BasicBlock *> seen;
  llvm::SmallVector<llvm::BasicBlock *, 16> worklist;
  worklist.push_back(start);

  while (!worklist.empty()) {
    llvm::BasicBlock *block = worklist.pop_back_val();
    if (block == nullptr || !seen.insert(block).second) {
      continue;
    }
    if (block == context.trap_block || dispatch_block_set.contains(block)) {
      continue;
    }
    if (block != start && instruction_block_set.contains(block)) {
      continue;
    }

    blocks.push_back(block);
    llvm::Instruction *terminator = block->getTerminator();
    if (terminator == nullptr || llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }
    for (llvm::BasicBlock *successor : llvm::successors(block)) {
      worklist.push_back(successor);
    }
  }
}

struct island_region_exits {
  llvm::SmallVector<llvm::BasicBlock *, 4> exits;
  bool exits_to_trap = false;
};

island_region_exits analyze_island_region_exits(
    llvm::ArrayRef<llvm::BasicBlock *> region_blocks,
    llvm::BasicBlock *trap_block) {
  island_region_exits result;
  llvm::DenseSet<llvm::BasicBlock *> region_set;
  for (llvm::BasicBlock *block : region_blocks) {
    region_set.insert(block);
    if (block == trap_block) {
      result.exits_to_trap = true;
    }
  }

  llvm::DenseSet<llvm::BasicBlock *> exit_set;
  for (llvm::BasicBlock *block : region_blocks) {
    llvm::Instruction *terminator = block->getTerminator();
    if (terminator == nullptr) {
      continue;
    }
    for (llvm::BasicBlock *successor : llvm::successors(block)) {
      if (region_set.contains(successor)) {
        continue;
      }
      if (successor == trap_block) {
        result.exits_to_trap = true;
      }
      if (exit_set.insert(successor).second) {
        result.exits.push_back(successor);
      }
    }
  }

  return result;
}

bool region_uses_blockaddress(llvm::ArrayRef<llvm::BasicBlock *> region_blocks) {
  for (llvm::BasicBlock *block : region_blocks) {
    for (llvm::Instruction &instruction : *block) {
      for (llvm::Use &operand : instruction.operands()) {
        if (llvm::isa<llvm::BlockAddress>(operand.get())) {
          return true;
        }
      }
    }
  }
  return false;
}

bool region_has_disallowed_control(llvm::ArrayRef<llvm::BasicBlock *> region_blocks) {
  for (llvm::BasicBlock *block : region_blocks) {
    if (block->isEHPad()) {
      return true;
    }
    for (llvm::Instruction &instruction : *block) {
      if (llvm::isa<llvm::AllocaInst, llvm::IndirectBrInst, llvm::InvokeInst,
                    llvm::CallBrInst, llvm::CatchReturnInst,
                    llvm::CleanupReturnInst, llvm::CatchSwitchInst,
                    llvm::ResumeInst>(instruction)) {
        return true;
      }
    }
  }
  return false;
}

bool is_safe_single_exit_island_region(
    llvm::ArrayRef<llvm::BasicBlock *> region_blocks, llvm::BasicBlock *entry,
    llvm::BasicBlock *trap_block,
    const llvm::DenseSet<llvm::BasicBlock *> &dispatch_block_set) {
  if (entry == nullptr || region_blocks.empty()) {
    return false;
  }

  llvm::DenseSet<llvm::BasicBlock *> region_set;
  for (llvm::BasicBlock *block : region_blocks) {
    if (block == nullptr || block == trap_block || dispatch_block_set.contains(block)) {
      return false;
    }
    region_set.insert(block);
  }
  if (!region_set.contains(entry)) {
    return false;
  }

  for (llvm::BasicBlock *block : region_blocks) {
    for (llvm::BasicBlock *predecessor : llvm::predecessors(block)) {
      if (!region_set.contains(predecessor) && block != entry) {
        return false;
      }
    }
  }

  const island_region_exits exits =
      analyze_island_region_exits(region_blocks, trap_block);
  if (exits.exits_to_trap || exits.exits.size() != 1 || exits.exits.front() == trap_block) {
    return false;
  }

  if (region_has_disallowed_control(region_blocks) ||
      region_uses_blockaddress(region_blocks)) {
    return false;
  }

  return true;
}

llvm::BasicBlock *find_instruction_handler_entry(llvm::BasicBlock *instruction_block,
                                                 llvm::BasicBlock *trap_block) {
  if (instruction_block == nullptr) {
    return nullptr;
  }
  auto *branch = llvm::dyn_cast<llvm::BranchInst>(instruction_block->getTerminator());
  if (branch == nullptr || !branch->isConditional()) {
    return nullptr;
  }

  llvm::BasicBlock *successor0 = branch->getSuccessor(0);
  llvm::BasicBlock *successor1 = branch->getSuccessor(1);
  if (successor0 == trap_block && successor1 != trap_block) {
    return successor1;
  }
  if (successor1 == trap_block && successor0 != trap_block) {
    return successor0;
  }
  return nullptr;
}

std::string make_vm_island_helper_name(llvm::Module &module,
                                        const rewrite_function_context &context,
                                        std::uint64_t island_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_h", "", mix_seed(context.bytecode_seed,
                                          0x151a0000ULL + island_index));
}

std::string make_vm_island_helper_name(llvm::Module &module,
                                        std::uint64_t bytecode_seed,
                                        std::uint64_t island_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_h", "",
      mix_seed(bytecode_seed, 0x151c0000ULL + island_index));
}

std::string make_vm_subisland_helper_name(llvm::Module &module,
                                          std::uint64_t bytecode_seed,
                                          std::uint64_t island_index,
                                          std::uint64_t subisland_index) {
  return obf::make_unique_obf_symbol_name(
      module, "__obf_vm_hs", "",
      mix_seed(bytecode_seed, 0x151e0000ULL + island_index * 0x100ULL +
                                  subisland_index));
}

bool should_use_state_islands(const bytecode_program &program,
                              vm_island_topology topology,
                              std::uint32_t island_count) {
  return topology == vm_island_topology::helper_shards && island_count >= 3 &&
         program.instructions.size() >= vm_island_min_instruction_count;
}

std::vector<std::uint32_t>
assign_vm_instruction_islands(const bytecode_program &program,
                              std::uint64_t bytecode_seed,
                              std::uint32_t island_count) {
  std::vector<std::uint32_t> island_for_instruction(program.instructions.size(), 0);
  if (island_count == 0 || program.instructions.empty()) {
    return island_for_instruction;
  }

  std::vector<std::size_t> order(program.instructions.size());
  std::iota(order.begin(), order.end(), 0);
  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs,
                                                   std::size_t rhs) {
    const std::uint64_t lhs_key = mix_seed(bytecode_seed, 0x151c1000ULL + lhs);
    const std::uint64_t rhs_key = mix_seed(bytecode_seed, 0x151c1000ULL + rhs);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  for (std::size_t position = 0; position < order.size(); ++position) {
    island_for_instruction[order[position]] =
        static_cast<std::uint32_t>(position % island_count);
  }
  return island_for_instruction;
}

std::uint32_t estimate_instruction_lowering_cost(
    const micro_instruction &instruction, const bytecode_layout &layout) {
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

struct subisland_plan {
  std::vector<std::uint32_t> subhelper_for_instruction;
  llvm::SmallVector<llvm::SmallVector<std::size_t, 16>, 8> instructions;
  llvm::SmallVector<std::uint32_t, 8> route_order;
  bool capped = false;
  bool enabled() const { return instructions.size() >= 2; }
};

llvm::SmallVector<std::size_t, 32> collect_island_instruction_indices(
    const bytecode_program &program,
    llvm::ArrayRef<std::uint32_t> island_for_instruction,
    std::uint32_t island_index) {
  llvm::SmallVector<std::size_t, 32> owned;
  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    if (island_for_instruction[instruction_index] == island_index) {
      owned.push_back(instruction_index);
    }
  }
  return owned;
}

subisland_plan build_subisland_plan(
    const bytecode_program &program, const serialized_bytecode_program &serialized,
    llvm::ArrayRef<std::size_t> owned_instructions, std::uint64_t bytecode_seed,
    std::uint32_t island_index) {
  subisland_plan plan;
  plan.subhelper_for_instruction.assign(program.instructions.size(), invalid_slot);
  if (owned_instructions.size() < vm_subisland_min_instruction_count) {
    return plan;
  }

  const std::uint64_t split_seed = mix_seed(bytecode_seed,
                                           0x151e1000ULL + island_index);
  std::uint64_t total_cost = 0;
  for (std::size_t instruction_index : owned_instructions) {
    total_cost += estimate_instruction_lowering_cost(
        program.instructions[instruction_index], serialized.layouts[instruction_index]);
  }

  const std::uint32_t seeded_target =
      static_cast<std::uint32_t>(vm_subisland_target_instruction_count +
                                 (split_seed % 5ULL));
  const std::uint32_t by_instruction_count = static_cast<std::uint32_t>(
      (owned_instructions.size() + seeded_target - 1U) / seeded_target);
  const std::uint64_t cost_target =
      static_cast<std::uint64_t>(seeded_target) * 12ULL;
  const std::uint32_t by_cost = static_cast<std::uint32_t>(
      (total_cost + cost_target - 1ULL) / cost_target);
  std::uint32_t subhelper_count = std::max<std::uint32_t>(2U,
                                                          std::max(by_instruction_count, by_cost));
  if (subhelper_count > vm_subisland_max_count) {
    subhelper_count = static_cast<std::uint32_t>(vm_subisland_max_count);
    plan.capped = true;
  }
  if (subhelper_count < 2U) {
    return plan;
  }

  plan.instructions.resize(subhelper_count);
  plan.route_order.reserve(subhelper_count);
  for (std::uint32_t subhelper_index = 0; subhelper_index < subhelper_count;
       ++subhelper_index) {
    plan.route_order.push_back(subhelper_index);
  }
  std::stable_sort(plan.route_order.begin(), plan.route_order.end(),
                   [&](std::uint32_t lhs, std::uint32_t rhs) {
                     const std::uint64_t lhs_key = mix_seed(
                         split_seed, 0x51570000ULL + lhs);
                     const std::uint64_t rhs_key = mix_seed(
                         split_seed, 0x51570000ULL + rhs);
                     return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
                   });

  llvm::SmallVector<std::size_t, 64> order(owned_instructions.begin(),
                                           owned_instructions.end());
  const bool family_biased = (split_seed & 1ULL) != 0;
  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs,
                                                   std::size_t rhs) {
    const std::uint64_t lhs_key = mix_seed(split_seed, 0x51571000ULL + lhs);
    const std::uint64_t rhs_key = mix_seed(split_seed, 0x51571000ULL + rhs);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  llvm::SmallVector<std::uint64_t, 8> bucket_costs(subhelper_count, 0);
  for (std::size_t instruction_index : order) {
    const std::uint32_t cost = estimate_instruction_lowering_cost(
        program.instructions[instruction_index], serialized.layouts[instruction_index]);
    const std::uint32_t preferred = family_biased
                                        ? opcode_family(program.instructions[instruction_index].op) %
                                              subhelper_count
                                        : static_cast<std::uint32_t>(
                                              mix_seed(split_seed, instruction_index) %
                                              subhelper_count);
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

  plan.instructions.erase(
      std::remove_if(plan.instructions.begin(), plan.instructions.end(),
                     [](const llvm::SmallVector<std::size_t, 16> &indices) {
                       return indices.empty();
                     }),
      plan.instructions.end());
  if (plan.instructions.size() < 2) {
    plan.instructions.clear();
    plan.route_order.clear();
    std::fill(plan.subhelper_for_instruction.begin(),
              plan.subhelper_for_instruction.end(), invalid_slot);
    return plan;
  }

  std::fill(plan.subhelper_for_instruction.begin(),
            plan.subhelper_for_instruction.end(), invalid_slot);
  plan.route_order.clear();
  for (std::uint32_t subhelper_index = 0;
       subhelper_index < plan.instructions.size(); ++subhelper_index) {
    plan.route_order.push_back(subhelper_index);
    for (std::size_t instruction_index : plan.instructions[subhelper_index]) {
      plan.subhelper_for_instruction[instruction_index] = subhelper_index;
    }
  }
  std::stable_sort(plan.route_order.begin(), plan.route_order.end(),
                   [&](std::uint32_t lhs, std::uint32_t rhs) {
                     const std::uint64_t lhs_key = mix_seed(
                         split_seed, 0x51572000ULL + lhs);
                     const std::uint64_t rhs_key = mix_seed(
                         split_seed, 0x51572000ULL + rhs);
                     return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
                   });

  return plan;
}

llvm::GlobalVariable *clone_bytecode_global_for_subhelper(
    llvm::GlobalVariable *bytecode_global, std::uint32_t subhelper_index) {
  if (bytecode_global == nullptr) {
    return nullptr;
  }
  llvm::Module *module = bytecode_global->getParent();
  auto *clone = new llvm::GlobalVariable(
      *module, bytecode_global->getValueType(), true,
      llvm::GlobalValue::PrivateLinkage, bytecode_global->getInitializer(),
      bytecode_global->getName().str() + "_h" + std::to_string(subhelper_index));
  clone->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  return clone;
}

vm_state_layout build_vm_state_layout(llvm::LLVMContext &context,
                                      llvm::Type *return_type,
                                      const bytecode_program &program) {
  vm_state_layout layout;
  llvm::SmallVector<llvm::Type *, 64> fields;
  fields.push_back(llvm::Type::getInt64Ty(context));
  fields.push_back(llvm::Type::getInt32Ty(context));
  fields.push_back(llvm::Type::getInt32Ty(context));
  fields.push_back(llvm::Type::getInt64Ty(context));
  if (!return_type->isVoidTy()) {
    layout.return_value_field = static_cast<std::uint32_t>(fields.size());
    fields.push_back(return_type);
  }

  layout.slot_fields.resize(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    for (std::uint32_t cell_index = 0; cell_index < vm_slot_rotation_cell_count;
         ++cell_index) {
      layout.slot_fields[slot_index][cell_index] =
          static_cast<std::uint32_t>(fields.size());
      fields.push_back(const_cast<llvm::Type *>(program.slots[slot_index].type));
    }
  }

  layout.type = llvm::StructType::get(context, fields);
  return layout;
}

llvm::Value *create_state_field_ptr(llvm::IRBuilder<> &builder,
                                    const vm_state_layout &layout,
                                    llvm::Value *state_storage,
                                    std::uint32_t field_index,
                                    llvm::StringRef name) {
  return builder.CreateStructGEP(layout.type, state_storage, field_index, name);
}

slot_storage build_state_slot_storage(llvm::IRBuilder<> &builder,
                                      const vm_state_layout &layout,
                                      llvm::Value *state_storage,
                                      const bytecode_program &program,
                                      llvm::StringRef name_prefix) {
  slot_storage slots;
  slots.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    slot_cells cells;
    cells.reserve(vm_slot_rotation_cell_count);
    for (std::uint32_t cell_index = 0; cell_index < vm_slot_rotation_cell_count;
         ++cell_index) {
      cells.push_back(create_state_field_ptr(
          builder, layout, state_storage,
          layout.slot_fields[slot_index][cell_index],
          (name_prefix + ".slot." + llvm::Twine(slot_index) + "." +
           llvm::Twine(cell_index))
              .str()));
    }
    slots.push_back(std::move(cells));
  }
  return slots;
}

llvm::Value *build_hidden_token_storage_value(
    llvm::IRBuilder<> &builder, llvm::Argument *hidden_token_arg,
    std::uint64_t fallback_seed) {
  if (hidden_token_arg == nullptr) {
    return builder.getInt64(fallback_seed);
  }
  llvm::Value *token = hidden_token_arg;
  if (token->getType() != builder.getInt64Ty()) {
    token = builder.CreateZExtOrTrunc(token, builder.getInt64Ty(),
                                      "obf.vm.island.token.cast");
  }
  return token;
}

void emit_state_instruction_dispatcher(
    llvm::Function &dispatcher, const bytecode_program &program,
    const virtualization_options &options, const vm_state_layout &state_layout,
    llvm::GlobalVariable *bytecode_global, llvm::GlobalVariable *retkey_global,
    const std::vector<slot_cell_mapping> &slot_mappings,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    const serialized_bytecode_program &serialized, const opcode_permutation &opcode_map,
    std::uint64_t opaque_seed_base, std::uint64_t bytecode_seed,
    llvm::ArrayRef<std::uint32_t> island_for_instruction,
    std::uint32_t island_index, std::uint32_t subhelper_index,
    llvm::ArrayRef<std::size_t> owned_instructions, bool subhelper) {
  llvm::LLVMContext &context = dispatcher.getContext();
  llvm::Module *module = dispatcher.getParent();
  const std::string route_prefix = subhelper ? "vm.island.subhelper."
                                             : "vm.island.";
  const std::string entry_name =
      route_prefix + "entry." + std::to_string(island_index) + "." +
      std::to_string(subhelper_index);
  const std::string trap_name =
      route_prefix + "trap." + std::to_string(island_index) + "." +
      std::to_string(subhelper_index);
  llvm::BasicBlock *entry_block = llvm::BasicBlock::Create(
      context, entry_name, &dispatcher);
  llvm::BasicBlock *trap_block = llvm::BasicBlock::Create(
      context, trap_name, &dispatcher);

  llvm::IRBuilder<> entry_builder(entry_block);
  llvm::Argument *state_arg = &*dispatcher.arg_begin();
  state_arg->setName(subhelper ? "vm.island.subhelper.state"
                               : "vm.island.state");
  slot_storage helper_slots = build_state_slot_storage(
      entry_builder, state_layout, state_arg, program, "vm.island.state");
  llvm::Value *state_slot = create_state_field_ptr(
      entry_builder, state_layout, state_arg, state_layout.bytecode_state_field,
      "vm.island.state.bc");
  llvm::Value *dispatch_index_slot = create_state_field_ptr(
      entry_builder, state_layout, state_arg, state_layout.dispatch_index_field,
      "vm.island.state.dispatch");
  llvm::Value *island_id_slot = create_state_field_ptr(
      entry_builder, state_layout, state_arg, state_layout.island_id_field,
      "vm.island.state.island");
  llvm::Value *hidden_token_slot = create_state_field_ptr(
      entry_builder, state_layout, state_arg, state_layout.hidden_token_field,
      "vm.island.state.token");
  llvm::Value *return_value_slot = nullptr;
  if (state_layout.return_value_field != invalid_slot) {
    return_value_slot = create_state_field_ptr(
        entry_builder, state_layout, state_arg, state_layout.return_value_field,
        "vm.island.state.ret");
  }

  llvm::SmallVector<llvm::BasicBlock *, 64> instruction_blocks(
      program.instructions.size(), nullptr);
  for (std::size_t instruction_index : owned_instructions) {
    instruction_blocks[instruction_index] = llvm::BasicBlock::Create(
        context, route_prefix + std::to_string(island_index) + "." +
                     std::to_string(subhelper_index) + "." +
                     std::to_string(instruction_index),
        &dispatcher);
  }

  llvm::Value *initial_dispatch = entry_builder.CreateLoad(
      entry_builder.getInt32Ty(), dispatch_index_slot,
      subhelper ? "vm.island.subroute.dispatch" : "vm.island.helper.dispatch");
  initial_dispatch = apply_vm_helper_dispatch_choreography(
      entry_builder, dispatcher, bytecode_seed, initial_dispatch,
      owned_instructions.size(),
      0x521000ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
          static_cast<std::uint64_t>(subhelper_index));
  auto *entry_switch = entry_builder.CreateSwitch(initial_dispatch, trap_block,
                                                    owned_instructions.size());
  for (std::size_t instruction_index : owned_instructions) {
    entry_switch->addCase(
        entry_builder.getInt32(dispatch_index_for_instruction[instruction_index]),
        instruction_blocks[instruction_index]);
  }

  const mba::builder_context mba_context{
      .entropy_anchor = mba::get_or_create_entropy_anchor(*module),
      .seed_base = opaque_seed_base,
      .depth = options.mba_depth};
  std::size_t dispatch_site_counter = 0;
  std::vector<switch_dispatch_bank> switch_dispatch_banks;
  const std::uint32_t island_count = island_for_instruction.empty()
                                         ? 0U
                                         : static_cast<std::uint32_t>(
                                               *std::max_element(
                                                   island_for_instruction.begin(),
                                                   island_for_instruction.end()) +
                                               1U);
  rewrite_function_context rewrite_context{
      .function = dispatcher,
      .program = program,
      .slot_allocas = helper_slots,
      .slot_mappings = slot_mappings,
      .opaque_seed_slot = nullptr,
      .opaque_seed_base = opaque_seed_base,
      .mba_context = mba_context,
      .hidden_token_arg = nullptr,
      .bytecode_seed = bytecode_seed,
      .opcode_map = opcode_map,
      .dispatch_backend = dispatch_backend_variant::switch_index,
      .dispatch_shape = vm_dispatcher_shape::switch_biased,
      .island_topology = vm_island_topology::helper_shards,
      .island_count = island_count,
      .switch_dispatch_bank_count = 1,
      .dispatch_index_for_instruction = dispatch_index_for_instruction,
      .bytecode_global = bytecode_global,
      .retkey_global = retkey_global,
      .state_layout = &state_layout,
      .state_storage = state_arg,
      .state_slot = state_slot,
      .dispatch_index_slot = dispatch_index_slot,
      .island_id_slot = island_id_slot,
      .hidden_token_slot = hidden_token_slot,
      .return_value_slot = return_value_slot,
      .trap_block = trap_block,
      .instruction_blocks = instruction_blocks,
      .island_for_instruction = island_for_instruction,
      .state_island_body = true,
      .dispatch_table = nullptr,
      .dispatch_table_type = nullptr,
      .ptr_int_type = module->getDataLayout().getIntPtrType(context),
      .switch_dispatch_banks = switch_dispatch_banks,
      .dispatch_site_counter = dispatch_site_counter,
  };

  for (std::size_t instruction_index : owned_instructions) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> header_builder(instruction_blocks[instruction_index]);
    const bytecode_layout &layout = serialized.layouts[instruction_index];
    instruction_rewrite_context instruction_context{
        .function_context = rewrite_context,
        .instruction_index = instruction_index,
        .instruction = instruction,
        .layout = layout,
        .current_slot_mapping = llvm::ArrayRef<std::uint32_t>(
            slot_mappings[instruction_index]),
    };

    llvm::Value *decoded_opcode = consume_metadata(
        header_builder, rewrite_context, layout,
        0x8000 + static_cast<std::uint64_t>(instruction_index) * 32);
    decoded_opcode->setName(subhelper ? "vm.island.subhelper.decode"
                                       : "vm.island.helper.decode");

    emit_instruction_integrity_probes(header_builder, instruction_context);

    auto *opcode_block = llvm::BasicBlock::Create(
        context, route_prefix + "exec." + std::to_string(island_index) + "." +
                     std::to_string(subhelper_index) + "." +
                     std::to_string(instruction_index),
        &dispatcher);
    llvm::Value *opcode_match = header_builder.CreateICmpEQ(
        decoded_opcode,
        header_builder.getInt8(get_physical_opcode(opcode_map, instruction.op)),
        "obf.vm.opcode.match");
    if (select_handler_variant(instruction.op, opaque_seed_base,
                               0x7d000 + instruction_index) == 0) {
      header_builder.CreateCondBr(opcode_match, opcode_block, trap_block);
    } else {
      llvm::Value *match_word = header_builder.CreateZExt(
          opcode_match, header_builder.getInt64Ty(), "obf.vm.opcode.match.word");
      llvm::Value *gated_match = mba::create_xor(
          header_builder, match_word,
          mba::create_opaque_integer(
              header_builder, header_builder.getInt64Ty(), mba_context,
              llvm::APInt(64, 0), 0x7e000 + instruction_index,
              "obf.vm.opcode.zero"),
          mba_context, 0x7f000 + instruction_index, "obf.vm.opcode.gate");
      llvm::Value *accept = header_builder.CreateICmpNE(
          gated_match, header_builder.getInt64(0), "obf.vm.opcode.accept");
      header_builder.CreateCondBr(accept, opcode_block, trap_block);
    }

    llvm::IRBuilder<> builder(opcode_block);
    if (lower_scalar_instruction(builder, instruction_context)) {
      continue;
    }
    if (lower_memory_instruction(builder, instruction_context)) {
      continue;
    }
    if (lower_control_instruction(builder, instruction_context)) {
      continue;
    }

    llvm_unreachable("unsupported vm opcode during island rewrite");
  }

  llvm::IRBuilder<> trap_builder(trap_block);
  trap_builder.CreateRet(apply_vm_island_status_choreography(
      trap_builder, dispatcher, bytecode_seed,
      trap_builder.getInt32(vm_island_trap_status), island_index,
      0x521100ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
          static_cast<std::uint64_t>(subhelper_index)));
}

void emit_split_state_island_router(
    llvm::Function &helper, const vm_state_layout &state_layout,
    std::uint64_t bytecode_seed,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    llvm::ArrayRef<std::uint32_t> route_order,
    const subisland_plan &plan, llvm::ArrayRef<llvm::Function *> subhelpers,
    std::uint32_t island_index) {
  llvm::LLVMContext &context = helper.getContext();
  llvm::BasicBlock *entry_block = llvm::BasicBlock::Create(
      context, "vm.island.subroute.entry." + std::to_string(island_index),
      &helper);
  llvm::BasicBlock *trap_block = llvm::BasicBlock::Create(
      context, "vm.island.subroute.trap." + std::to_string(island_index),
      &helper);
  llvm::IRBuilder<> entry_builder(entry_block);
  llvm::Argument *state_arg = &*helper.arg_begin();
  state_arg->setName("vm.island.state");
  llvm::Value *dispatch_index_slot = create_state_field_ptr(
      entry_builder, state_layout, state_arg, state_layout.dispatch_index_field,
      "vm.island.state.dispatch");
  llvm::Value *initial_dispatch = entry_builder.CreateLoad(
      entry_builder.getInt32Ty(), dispatch_index_slot, "vm.island.subroute");
  initial_dispatch = apply_vm_helper_dispatch_choreography(
      entry_builder, helper, bytecode_seed,
      initial_dispatch, plan.subhelper_for_instruction.size(),
      0x521200ULL + island_index);
  auto *route_switch = entry_builder.CreateSwitch(initial_dispatch, trap_block,
                                                    plan.subhelper_for_instruction.size());

  for (std::uint32_t subhelper_index : route_order) {
    auto *call_block = llvm::BasicBlock::Create(
        context, "vm.island.subroute.call." + std::to_string(island_index) + "." +
                     std::to_string(subhelper_index),
        &helper);
    for (std::size_t instruction_index : plan.instructions[subhelper_index]) {
      route_switch->addCase(
          entry_builder.getInt32(dispatch_index_for_instruction[instruction_index]),
          call_block);
    }

    llvm::IRBuilder<> call_builder(call_block);
    auto *status = call_builder.CreateCall(
        subhelpers[subhelper_index]->getFunctionType(), subhelpers[subhelper_index],
        {state_arg}, "vm.island.subroute.status");
    call_builder.CreateRet(apply_vm_island_status_choreography(
        call_builder, helper, bytecode_seed, status, subhelper_index,
        0x521300ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
            static_cast<std::uint64_t>(subhelper_index)));
  }

  llvm::IRBuilder<> trap_builder(trap_block);
  trap_builder.CreateRet(apply_vm_island_status_choreography(
      trap_builder, helper, bytecode_seed,
      trap_builder.getInt32(vm_island_trap_status),
      island_index, 0x521400ULL + island_index));
}

void emit_state_island_helper(
    llvm::Function &helper, const bytecode_program &program,
    const virtualization_options &options, const vm_state_layout &state_layout,
    llvm::GlobalVariable *bytecode_global, llvm::GlobalVariable *retkey_global,
    const std::vector<slot_cell_mapping> &slot_mappings,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    llvm::ArrayRef<std::uint64_t> entry_states,
    const serialized_bytecode_program &serialized, const opcode_permutation &opcode_map,
    std::uint64_t opaque_seed_base, std::uint64_t bytecode_seed,
    llvm::Argument *hidden_token_arg,
    llvm::ArrayRef<std::uint32_t> island_for_instruction,
    std::uint32_t island_index) {
  (void)entry_states;
  (void)hidden_token_arg;

  const llvm::SmallVector<std::size_t, 32> owned_instructions =
      collect_island_instruction_indices(program, island_for_instruction,
                                         island_index);
  subisland_plan split_plan = build_subisland_plan(
      program, serialized, owned_instructions, bytecode_seed, island_index);
  if (!split_plan.enabled()) {
    emit_state_instruction_dispatcher(
        helper, program, options, state_layout, bytecode_global, retkey_global,
        slot_mappings, dispatch_index_for_instruction, serialized, opcode_map,
        opaque_seed_base, bytecode_seed, island_for_instruction, island_index, 0,
        owned_instructions, false);
    return;
  }

  helper.addFnAttr("vm.island.helper.split");
  helper.addFnAttr("vm.island.helper.large");
  helper.addFnAttr("vm.island.subroute");
  if (split_plan.capped) {
    helper.addFnAttr("vm.island.helper.cap");
  }

  llvm::LLVMContext &context = helper.getContext();
  llvm::Module *module = helper.getParent();
  auto *state_pointer_type = llvm::PointerType::get(context, 0);
  auto *helper_type = llvm::FunctionType::get(llvm::Type::getInt32Ty(context),
                                              {state_pointer_type}, false);
  llvm::SmallVector<llvm::Function *, 8> subhelpers;
  subhelpers.resize(split_plan.instructions.size(), nullptr);

  for (std::uint32_t subhelper_index = 0;
       subhelper_index < split_plan.instructions.size(); ++subhelper_index) {
    llvm::Function *subhelper = llvm::Function::Create(
        helper_type, llvm::GlobalValue::InternalLinkage,
        make_vm_subisland_helper_name(*module, bytecode_seed, island_index,
                                      subhelper_index),
        module);
    subhelper->setDSOLocal(true);
    subhelper->addFnAttr(llvm::Attribute::NoInline);
    subhelper->addFnAttr("instcombine-no-verify-fixpoint");
    subhelper->addFnAttr("vm.dispatch.shape.switch");
    subhelper->addFnAttr("vm.island.helper");
    subhelper->addFnAttr("vm.island.helper.decode");
    subhelper->addFnAttr("vm.island.helper.dispatch");
    subhelper->addFnAttr("vm.island.helper.table");
    subhelper->addFnAttr("vm.island.next_island");
    subhelper->addFnAttr("vm.island.state");
    subhelper->addFnAttr("vm.island.subhelper");
    subhelper->addFnAttr("vm.island.subroute");
    subhelper->addFnAttr("vm.island.subtable.shard");
    subhelper->addFnAttr("vm.island.table.shard");
    subhelpers[subhelper_index] = subhelper;
  }

  emit_split_state_island_router(
      helper, state_layout, bytecode_seed, dispatch_index_for_instruction,
      split_plan.route_order,
      split_plan, subhelpers, island_index);

  for (std::uint32_t subhelper_index = 0;
       subhelper_index < split_plan.instructions.size(); ++subhelper_index) {
    llvm::GlobalVariable *subhelper_bytecode = clone_bytecode_global_for_subhelper(
        bytecode_global, subhelper_index);
    emit_state_instruction_dispatcher(
        *subhelpers[subhelper_index], program, options, state_layout,
        subhelper_bytecode, retkey_global, slot_mappings,
        dispatch_index_for_instruction, serialized, opcode_map, opaque_seed_base,
        bytecode_seed, island_for_instruction, island_index, subhelper_index,
        split_plan.instructions[subhelper_index], true);
  }
}

void rewrite_function_body_state_islands(
    llvm::Function &function, const bytecode_program &program,
    const virtualization_options &options, llvm::StringRef symbol_tag,
    llvm::ArrayRef<llvm::BasicBlock *> old_blocks,
    std::uint64_t opaque_seed_base, std::uint64_t bytecode_seed,
    const opcode_permutation &opcode_map, std::uint32_t island_count) {
  for (llvm::BasicBlock *block : old_blocks) {
    block->dropAllReferences();
  }
  for (llvm::BasicBlock *block : old_blocks) {
    block->eraseFromParent();
  }

  llvm::LLVMContext &context = function.getContext();
  llvm::Module *module = function.getParent();
  auto *entry_block = llvm::BasicBlock::Create(context, "entry.obf.vm", &function);
  auto *route_block = llvm::BasicBlock::Create(context, "vm.island.route.entry",
                                               &function);
  auto *finish_block = llvm::BasicBlock::Create(context, "vm.island.done",
                                                &function);
  auto *trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);
  llvm::IRBuilder<> entry_builder(entry_block);

  vm_state_layout state_layout = build_vm_state_layout(
      context, function.getReturnType(), program);
  auto *state_storage = entry_builder.CreateAlloca(state_layout.type, nullptr,
                                                   "vm.island.state");
  llvm::Value *state_slot = create_state_field_ptr(
      entry_builder, state_layout, state_storage, state_layout.bytecode_state_field,
      "vm.island.state.bc");
  llvm::Value *dispatch_index_slot = create_state_field_ptr(
      entry_builder, state_layout, state_storage, state_layout.dispatch_index_field,
      "vm.island.state.dispatch");
  llvm::Value *island_id_slot = create_state_field_ptr(
      entry_builder, state_layout, state_storage, state_layout.island_id_field,
      "vm.island.state.island");
  llvm::Value *hidden_token_slot = create_state_field_ptr(
      entry_builder, state_layout, state_storage, state_layout.hidden_token_field,
      "vm.island.state.token");
  llvm::Value *return_value_slot = nullptr;
  if (state_layout.return_value_field != invalid_slot) {
    return_value_slot = create_state_field_ptr(
        entry_builder, state_layout, state_storage, state_layout.return_value_field,
        "vm.island.state.ret");
    entry_builder.CreateStore(
        llvm::Constant::getNullValue(function.getReturnType()), return_value_slot);
  }

  slot_storage state_slots = build_state_slot_storage(
      entry_builder, state_layout, state_storage, program, "vm.island.state");
  const std::vector<slot_cell_mapping> slot_mappings =
      build_slot_cell_mappings(program, opaque_seed_base);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed,
                               dispatch_backend_variant::switch_index);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed,
      opcode_map);
  const std::vector<std::uint32_t> island_for_instruction =
      assign_vm_instruction_islands(program, bytecode_seed, island_count);

  llvm::SmallVector<llvm::GlobalVariable *, 8> bytecode_globals;
  bytecode_globals.resize(island_count, nullptr);
  if (!serialized.bytes.empty()) {
    auto *bytecode_type =
        llvm::ArrayType::get(entry_builder.getInt8Ty(), serialized.bytes.size());
    llvm::Constant *bytecode_initializer =
        llvm::ConstantDataArray::get(context, serialized.bytes);
    for (std::uint32_t island_index = 0; island_index < island_count;
         ++island_index) {
      llvm::GlobalVariable *bytecode_global = new llvm::GlobalVariable(
          *module, bytecode_type, true, llvm::GlobalValue::PrivateLinkage,
          bytecode_initializer,
          "__obf_vm_bc_" + symbol_tag.str() + "_s" +
              std::to_string(island_index));
      bytecode_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
      bytecode_globals[island_index] = bytecode_global;
    }
  }

  llvm::GlobalVariable *retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value = derive_vm_return_key(function, program);
    const std::string retkey_name = "__obf_vm_retkey_" + symbol_tag.str();
    retkey_global = module->getNamedGlobal(retkey_name);
    if (retkey_global == nullptr) {
      retkey_global = new llvm::GlobalVariable(
          *module, entry_builder.getInt64Ty(), false,
          llvm::GlobalValue::PrivateLinkage, entry_builder.getInt64(retkey_value),
          retkey_name);
    } else {
      retkey_global->setInitializer(entry_builder.getInt64(retkey_value));
      retkey_global->setConstant(false);
      retkey_global->setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  llvm::Argument *hidden_token_arg = nullptr;
  if (options.hidden_token_handshake && function.arg_size() > 0) {
    hidden_token_arg = &*std::prev(function.arg_end());
  }
  entry_builder.CreateStore(
      build_hidden_token_storage_value(entry_builder, hidden_token_arg,
                                       opaque_seed_base),
      hidden_token_slot);

  const std::uint32_t entry_instruction =
      program.blocks.empty() ? 0 : program.blocks.front().first_instruction;
  const slot_cell_mapping entry_identity_mapping(program.slots.size(), 0);
  llvm::ArrayRef<std::uint32_t> entry_slot_mapping = entry_identity_mapping;
  if (!slot_mappings.empty()) {
    entry_slot_mapping = slot_mappings[entry_instruction];
  }

  const mba::builder_context mba_context{
      .entropy_anchor = mba::get_or_create_entropy_anchor(*module),
      .seed_base = opaque_seed_base,
      .depth = options.mba_depth};
  entry_builder.CreateStore(
      build_hidden_token_seed(
          entry_builder, hidden_token_arg,
          program.instructions.empty() ? bytecode_seed : entry_states[entry_instruction],
          options.valid_hidden_tokens, mba_context, 0x3100,
          "obf.vm.token.state"),
      state_slot);
  entry_builder.CreateStore(
      entry_builder.getInt32(dispatch_index_for_instruction[entry_instruction]),
      dispatch_index_slot);
  entry_builder.CreateStore(
      entry_builder.getInt32(island_for_instruction[entry_instruction]),
      island_id_slot);

  std::size_t argument_index = 0;
  for (llvm::Argument &argument : function.args()) {
    store_slot(entry_builder, state_slots, entry_slot_mapping, program,
               program.argument_slots[argument_index], &argument, nullptr,
               opaque_seed_base, mba_context, 0x8110 + argument_index);
    ++argument_index;
  }

  llvm::SmallVector<llvm::Function *, 8> helpers;
  helpers.reserve(island_count);
  auto *state_pointer_type = llvm::PointerType::get(context, 0);
  auto *helper_type = llvm::FunctionType::get(entry_builder.getInt32Ty(),
                                              {state_pointer_type}, false);
  for (std::uint32_t island_index = 0; island_index < island_count;
       ++island_index) {
    llvm::Function *helper = llvm::Function::Create(
        helper_type, llvm::GlobalValue::InternalLinkage,
        make_vm_island_helper_name(*module, bytecode_seed, island_index), module);
    helper->setDSOLocal(true);
    helper->addFnAttr(llvm::Attribute::NoInline);
    helper->addFnAttr("instcombine-no-verify-fixpoint");
    helper->addFnAttr("vm.dispatch.shape.switch");
    helper->addFnAttr("vm.island.helper");
    helper->addFnAttr("vm.island.helper.decode");
    helper->addFnAttr("vm.island.helper.dispatch");
    helper->addFnAttr("vm.island.helper.table");
    helper->addFnAttr("vm.island.next_island");
    helper->addFnAttr("vm.island.state");
    helper->addFnAttr("vm.island.table.shard");
    helpers.push_back(helper);
  }

  entry_builder.CreateBr(route_block);
  llvm::IRBuilder<> route_builder(route_block);
  auto *status_phi = route_builder.CreatePHI(route_builder.getInt32Ty(),
                                              helpers.size() + 1,
                                              "vm.island.route.status");
  status_phi->addIncoming(route_builder.getInt32(vm_island_continue_status),
                          entry_block);
  auto *island_route_block = llvm::BasicBlock::Create(
      context, "vm.island.root.route", &function);
  auto *route_switch = route_builder.CreateSwitch(status_phi, trap_block, 3);
  route_switch->addCase(route_builder.getInt32(vm_island_continue_status),
                        island_route_block);
  route_switch->addCase(route_builder.getInt32(vm_island_done_status), finish_block);
  route_switch->addCase(route_builder.getInt32(vm_island_trap_status), trap_block);

  llvm::IRBuilder<> island_route_builder(island_route_block);
  llvm::Value *current_island = island_route_builder.CreateLoad(
      island_route_builder.getInt32Ty(), island_id_slot, "vm.island.root.route");
  auto *island_switch = island_route_builder.CreateSwitch(
      current_island, trap_block, helpers.size());

  for (std::uint32_t island_index = 0; island_index < helpers.size();
       ++island_index) {
    auto *call_block = llvm::BasicBlock::Create(
        context, "vm.island.call." + std::to_string(island_index), &function);
    island_switch->addCase(island_route_builder.getInt32(island_index), call_block);
    llvm::IRBuilder<> call_builder(call_block);
    auto *status = call_builder.CreateCall(helpers[island_index]->getFunctionType(),
                                            helpers[island_index], {state_storage},
                                           "vm.island.status");
    call_builder.CreateBr(route_block);
    status_phi->addIncoming(status, call_block);
  }

  llvm::IRBuilder<> finish_builder(finish_block);
  if (function.getReturnType()->isVoidTy()) {
    finish_builder.CreateRetVoid();
  } else {
    finish_builder.CreateRet(finish_builder.CreateLoad(
        function.getReturnType(), return_value_slot, "vm.island.root.finalize"));
  }

  llvm::IRBuilder<> trap_builder(trap_block);
  llvm::FunctionCallee trap = llvm::Intrinsic::getOrInsertDeclaration(
      module, llvm::Intrinsic::trap);
  trap_builder.CreateCall(trap);
  trap_builder.CreateUnreachable();

  for (std::uint32_t island_index = 0; island_index < helpers.size();
       ++island_index) {
    emit_state_island_helper(
        *helpers[island_index], program, options, state_layout,
        bytecode_globals[island_index],
        retkey_global, slot_mappings, dispatch_index_for_instruction, entry_states,
        serialized, opcode_map, opaque_seed_base, bytecode_seed, hidden_token_arg,
        island_for_instruction, island_index);
  }

  function.addFnAttr("vm.island.entry");
  function.addFnAttr("vm.island.topology.helper_shards");
  function.addFnAttr("vm.island.count." + std::to_string(helpers.size()));
  function.addFnAttr("vm.island.route");
  function.addFnAttr("vm.island.root.finalize");
  function.addFnAttr("vm.island.root.route");
  function.addFnAttr("vm.island.root.small");
  function.addFnAttr("vm.island.state");
}

void rewrite_function_body(llvm::Function &function,
                           const bytecode_program &program,
                           const virtualization_options &options) {
  llvm::LLVMContext &context = function.getContext();
  const std::string symbol_tag =
      options.symbol_tag.empty() ? function.getName().str() : options.symbol_tag;
  const llvm::AttributeList preserved_attributes =
      build_preserved_function_attributes(function);

  function.setAttributes(preserved_attributes);
  function.addFnAttr("instcombine-no-verify-fixpoint");

  llvm::SmallVector<llvm::BasicBlock *, 8> old_blocks;
  old_blocks.reserve(function.size());
  for (llvm::BasicBlock &block : function) {
    old_blocks.push_back(&block);
  }

  const std::uint64_t opaque_seed_base = derive_vm_opaque_seed(function, program);
  const std::uint64_t bytecode_seed = derive_vm_bytecode_seed(function, program);
  const opcode_permutation opcode_map = build_opcode_permutation(function, program);
  const vm_dispatcher_shape dispatch_shape = select_dispatcher_shape(
      bytecode_seed, opaque_seed_base ^ 0x26000ULL, program.instructions.size());
  const vm_island_topology island_topology = select_vm_island_topology(
      options.prefer_island_helpers, program.instructions.size(), bytecode_seed,
      opaque_seed_base ^ 0x26003ULL);
  const std::uint32_t island_count = select_vm_island_count(
      bytecode_seed, opaque_seed_base ^ 0x26002ULL, program.instructions.size(),
      island_topology);

  if (should_use_state_islands(program, island_topology, island_count)) {
    rewrite_function_body_state_islands(function, program, options, symbol_tag,
                                        old_blocks, opaque_seed_base, bytecode_seed,
                                        opcode_map, island_count);
    return;
  }

  for (llvm::BasicBlock *block : old_blocks) {
    block->dropAllReferences();
  }
  for (llvm::BasicBlock *block : old_blocks) {
    block->eraseFromParent();
  }

  auto *entry_block = llvm::BasicBlock::Create(context, "entry.obf.vm", &function);
  auto *trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);

  llvm::SmallVector<llvm::BasicBlock *, 32> instruction_blocks;
  instruction_blocks.reserve(program.instructions.size());
  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    instruction_blocks.push_back(llvm::BasicBlock::Create(
        context, "vm." + std::to_string(instruction_index), &function));
  }

  llvm::IRBuilder<> entry_builder(entry_block);
  slot_storage slot_allocas;
  slot_allocas.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    slot_cells cells;
    cells.reserve(vm_slot_rotation_cell_count);
    for (std::uint32_t cell_index = 0; cell_index < vm_slot_rotation_cell_count;
         ++cell_index) {
      cells.push_back(entry_builder.CreateAlloca(
          const_cast<llvm::Type *>(program.slots[slot_index].type), nullptr,
          "obf.vm.slot." + std::to_string(slot_index) + "." +
              std::to_string(cell_index)));
    }
    slot_allocas.push_back(std::move(cells));
  }

  const std::vector<slot_cell_mapping> slot_mappings =
      build_slot_cell_mappings(program, opaque_seed_base);
  llvm::AllocaInst *opaque_seed = nullptr;
  llvm::GlobalVariable *entropy_anchor =
      mba::get_or_create_entropy_anchor(*function.getParent());
  const mba::builder_context mba_context{.entropy_anchor = entropy_anchor,
                                         .seed_base = opaque_seed_base,
                                         .depth = options.mba_depth};

  llvm::Argument *hidden_token_arg = nullptr;
  if (options.hidden_token_handshake && function.arg_size() > 0) {
    hidden_token_arg = &*std::prev(function.arg_end());
  }

  dispatch_backend_variant dispatch_backend = dispatch_backend_variant::switch_index;
  vm_dispatcher_shape effective_dispatch_shape = dispatch_shape;
  if (island_topology == vm_island_topology::helper_shards) {
    effective_dispatch_shape = vm_dispatcher_shape::switch_biased;
  }
  if (effective_dispatch_shape == vm_dispatcher_shape::direct_threaded) {
    dispatch_backend = static_cast<dispatch_backend_variant>(
        select_dispatch_variant(bytecode_seed, opaque_seed_base ^ 0x26000ULL,
                                program.instructions.size()));
    if (dispatch_backend == dispatch_backend_variant::switch_index) {
      dispatch_backend = dispatch_backend_variant::direct_threaded_match;
    }
  }
  const std::uint32_t switch_dispatch_bank_count =
      select_switch_dispatch_bank_count(bytecode_seed, opaque_seed_base ^ 0x26001ULL,
                                        program.instructions.size(),
                                        effective_dispatch_shape);
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed, dispatch_backend);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed,
      opcode_map);

  llvm::GlobalVariable *bytecode_global = nullptr;
  if (!serialized.bytes.empty()) {
    auto *bytecode_type =
        llvm::ArrayType::get(entry_builder.getInt8Ty(), serialized.bytes.size());
    bytecode_global = new llvm::GlobalVariable(
        *function.getParent(), bytecode_type, true,
        llvm::GlobalValue::PrivateLinkage,
        llvm::ConstantDataArray::get(context, serialized.bytes),
        "__obf_vm_bc_" + symbol_tag);
    bytecode_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  }

  llvm::GlobalVariable *retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value = derive_vm_return_key(function, program);
    const std::string retkey_name = "__obf_vm_retkey_" + symbol_tag;
    retkey_global = function.getParent()->getNamedGlobal(retkey_name);
    if (retkey_global == nullptr) {
      retkey_global = new llvm::GlobalVariable(
          *function.getParent(), entry_builder.getInt64Ty(),
          /*isConstant=*/false, llvm::GlobalValue::PrivateLinkage,
          entry_builder.getInt64(retkey_value), retkey_name);
    } else {
      if (retkey_global->getValueType() != entry_builder.getInt64Ty()) {
        llvm_unreachable("vm retkey global has unexpected type");
      }
      retkey_global->setInitializer(entry_builder.getInt64(retkey_value));
      retkey_global->setConstant(false);
      retkey_global->setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  auto *state_slot =
      entry_builder.CreateAlloca(entry_builder.getInt64Ty(), nullptr, "obf.vm.state");

  const std::uint32_t entry_instruction =
      program.blocks.empty() ? 0 : program.blocks.front().first_instruction;
  const slot_cell_mapping entry_identity_mapping(program.slots.size(), 0);
  llvm::ArrayRef<std::uint32_t> entry_slot_mapping = entry_identity_mapping;
  if (!slot_mappings.empty()) {
    entry_slot_mapping = slot_mappings[entry_instruction];
  }
  (void)entry_builder.CreateStore(
      build_hidden_token_seed(
          entry_builder, hidden_token_arg,
          program.instructions.empty() ? bytecode_seed
                                       : entry_states[entry_instruction],
          options.valid_hidden_tokens, mba_context, 0x3100,
          "obf.vm.token.state"),
      state_slot);

  llvm::AllocaInst *dispatch_table = nullptr;
  llvm::ArrayType *dispatch_table_type = nullptr;
  llvm::IntegerType *ptr_int_type = nullptr;
  if (!instruction_blocks.empty()) {
    const llvm::DataLayout &data_layout = function.getParent()->getDataLayout();
    ptr_int_type = data_layout.getIntPtrType(context, function.getAddressSpace());
  }
  if (!instruction_blocks.empty() &&
      dispatch_backend != dispatch_backend_variant::switch_index) {
    dispatch_table_type =
        llvm::ArrayType::get(ptr_int_type, instruction_blocks.size());
    dispatch_table = entry_builder.CreateAlloca(dispatch_table_type, nullptr,
                                                "obf.vm.dispatch.table");
  }

  std::size_t argument_index = 0;
  for (llvm::Argument &argument : function.args()) {
    store_slot(entry_builder, slot_allocas, entry_slot_mapping, program,
               program.argument_slots[argument_index], &argument, opaque_seed,
               opaque_seed_base, mba_context, 0x8110 + argument_index);
    ++argument_index;
  }

  std::size_t dispatch_site_counter = 0;
  std::vector<switch_dispatch_bank> switch_dispatch_banks;
  rewrite_function_context rewrite_context{
      .function = function,
      .program = program,
      .slot_allocas = slot_allocas,
      .slot_mappings = slot_mappings,
      .opaque_seed_slot = opaque_seed,
      .opaque_seed_base = opaque_seed_base,
      .mba_context = mba_context,
      .hidden_token_arg = hidden_token_arg,
      .bytecode_seed = bytecode_seed,
      .opcode_map = opcode_map,
      .dispatch_backend = dispatch_backend,
      .dispatch_shape = effective_dispatch_shape,
      .island_topology = island_topology,
      .island_count = island_count,
      .switch_dispatch_bank_count = switch_dispatch_bank_count,
      .dispatch_index_for_instruction = dispatch_index_for_instruction,
      .bytecode_global = bytecode_global,
      .retkey_global = retkey_global,
      .state_slot = state_slot,
      .trap_block = trap_block,
      .instruction_blocks = instruction_blocks,
      .dispatch_table = dispatch_table,
      .dispatch_table_type = dispatch_table_type,
      .ptr_int_type = ptr_int_type,
      .switch_dispatch_banks = switch_dispatch_banks,
      .dispatch_site_counter = dispatch_site_counter,
  };

  initialize_dispatch_runtime(entry_builder, rewrite_context);

  if (instruction_blocks.empty()) {
    entry_builder.CreateBr(trap_block);
  } else {
    emit_dispatch(entry_builder, rewrite_context,
                  entry_builder.getInt32(
                      dispatch_index_for_instruction[entry_instruction]),
                  0x3000);
  }

  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> header_builder(instruction_blocks[instruction_index]);
    const bytecode_layout &layout = serialized.layouts[instruction_index];
    instruction_rewrite_context instruction_context{
        .function_context = rewrite_context,
        .instruction_index = instruction_index,
        .instruction = instruction,
        .layout = layout,
        .current_slot_mapping = llvm::ArrayRef<std::uint32_t>(
            slot_mappings[instruction_index]),
    };

    llvm::Value *decoded_opcode = consume_metadata(
        header_builder, rewrite_context, layout,
        0x8000 + static_cast<std::uint64_t>(instruction_index) * 32);

    emit_instruction_integrity_probes(header_builder, instruction_context);

    auto *opcode_block = llvm::BasicBlock::Create(
        context, "vm.exec." + std::to_string(instruction_index), &function);
    llvm::Value *opcode_match = header_builder.CreateICmpEQ(
        decoded_opcode,
        header_builder.getInt8(get_physical_opcode(opcode_map, instruction.op)),
        "obf.vm.opcode.match");
    if (select_handler_variant(instruction.op, opaque_seed_base,
                               0x7d000 + instruction_index) == 0) {
      header_builder.CreateCondBr(opcode_match, opcode_block, trap_block);
    } else {
      llvm::Value *match_word = header_builder.CreateZExt(
          opcode_match, header_builder.getInt64Ty(), "obf.vm.opcode.match.word");
      llvm::Value *gated_match = mba::create_xor(
          header_builder, match_word,
          mba::create_opaque_integer(
              header_builder, header_builder.getInt64Ty(), mba_context,
              llvm::APInt(64, 0), 0x7e000 + instruction_index,
              "obf.vm.opcode.zero"),
          mba_context, 0x7f000 + instruction_index, "obf.vm.opcode.gate");
      llvm::Value *accept = header_builder.CreateICmpNE(
          gated_match, header_builder.getInt64(0), "obf.vm.opcode.accept");
      header_builder.CreateCondBr(accept, opcode_block, trap_block);
    }

    llvm::IRBuilder<> builder(opcode_block);
    if (lower_scalar_instruction(builder, instruction_context)) {
      continue;
    }
    if (lower_memory_instruction(builder, instruction_context)) {
      continue;
    }
    if (lower_control_instruction(builder, instruction_context)) {
      continue;
    }

    llvm_unreachable("unsupported vm opcode during rewrite");
  }

  outline_vm_islands(rewrite_context);

  llvm::IRBuilder<> trap_builder(trap_block);
  llvm::FunctionCallee trap = llvm::Intrinsic::getOrInsertDeclaration(
      function.getParent(), llvm::Intrinsic::trap);
  trap_builder.CreateCall(trap);
  trap_builder.CreateUnreachable();
}

} // namespace

std::uint32_t outline_vm_islands(rewrite_function_context &context) {
  if (context.island_topology != vm_island_topology::helper_shards ||
      context.island_count < 2 || context.dispatch_backend !=
                                      dispatch_backend_variant::switch_index ||
      context.switch_dispatch_banks.size() != 1 || context.instruction_blocks.empty()) {
    return 0;
  }

  const switch_dispatch_bank &bank = context.switch_dispatch_banks.front();
  if (bank.switch_inst == nullptr || bank.dispatch_index_phi == nullptr) {
    return 0;
  }

  llvm::DenseSet<llvm::BasicBlock *> instruction_block_set;
  for (llvm::BasicBlock *block : context.instruction_blocks) {
    instruction_block_set.insert(block);
  }
  llvm::DenseSet<llvm::BasicBlock *> dispatch_block_set;
  for (const switch_dispatch_bank &dispatch_bank : context.switch_dispatch_banks) {
    dispatch_block_set.insert(dispatch_bank.block);
  }

  struct island_assignment {
    std::size_t instruction_index = 0;
    std::uint32_t island_index = 0;
    std::uint64_t rank = 0;
  };

  llvm::SmallVector<island_assignment, 64> assignments;
  for (std::size_t instruction_index = 0;
       instruction_index < context.program.instructions.size(); ++instruction_index) {
    if (!is_island_candidate_instruction(context.program.instructions[instruction_index])) {
      continue;
    }
    const std::uint64_t rank = mix_seed(
        context.bytecode_seed, 0x151a1000ULL + instruction_index);
    assignments.push_back(
        {.instruction_index = instruction_index,
         .island_index = static_cast<std::uint32_t>(rank % context.island_count),
         .rank = rank});
  }
  if (assignments.size() < context.island_count * 2U) {
    return 0;
  }

  std::stable_sort(assignments.begin(), assignments.end(),
                   [](const island_assignment &lhs,
                      const island_assignment &rhs) {
                     return lhs.rank == rhs.rank
                                ? lhs.instruction_index < rhs.instruction_index
                                : lhs.rank < rhs.rank;
                   });

  llvm::CodeExtractorAnalysisCache cache(context.function);
  llvm::DominatorTree dom_tree(context.function);
  llvm::LoopInfo loop_info(dom_tree);
  llvm::AssumptionCache assumption_cache(context.function);
  (void)loop_info;

  std::uint32_t extracted_count = 0;
  for (std::uint32_t island_index = 0; island_index < context.island_count;
       ++island_index) {
    llvm::SmallVector<std::size_t, 16> island_instructions;
    for (const island_assignment &assignment : assignments) {
      if (assignment.island_index == island_index) {
        island_instructions.push_back(assignment.instruction_index);
      }
    }
    if (island_instructions.size() < 2) {
      continue;
    }

    for (std::size_t instruction_index : island_instructions) {
      llvm::BasicBlock *handler_entry = find_instruction_handler_entry(
          context.instruction_blocks[instruction_index], context.trap_block);
      if (handler_entry == nullptr) {
        continue;
      }

      llvm::SmallVector<llvm::BasicBlock *, 32> region_blocks;
      collect_reachable_island_blocks(handler_entry, context, instruction_block_set,
                                      dispatch_block_set, region_blocks);

      llvm::DenseSet<llvm::BasicBlock *> unique_region_blocks;
      llvm::SmallVector<llvm::BasicBlock *, 32> deduped_region_blocks;
      for (llvm::BasicBlock *block : region_blocks) {
        if (unique_region_blocks.insert(block).second) {
          deduped_region_blocks.push_back(block);
        }
      }

      if (!is_safe_single_exit_island_region(deduped_region_blocks, handler_entry,
                                             context.trap_block, dispatch_block_set)) {
        continue;
      }

      dom_tree.recalculate(context.function);
      llvm::CodeExtractor extractor(
          deduped_region_blocks, &dom_tree, /*aggregate args=*/true,
          /*bfi=*/nullptr, /*bpi=*/nullptr, &assumption_cache,
          /*allow var args=*/false, /*allow alloca=*/false,
          /*allocation block=*/nullptr,
          make_vm_island_helper_name(*context.function.getParent(), context,
                                     island_index));
      if (!extractor.isEligible()) {
        dom_tree.recalculate(context.function);
        continue;
      }

      llvm::Function *helper = extractor.extractCodeRegion(cache);
      if (helper == nullptr) {
        dom_tree.recalculate(context.function);
        continue;
      }

      helper->setName(make_vm_island_helper_name(*context.function.getParent(),
                                                 context, 0x100ULL + island_index));
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
    context.function.addFnAttr("vm.island.count." +
                               std::to_string(extracted_count));
  }

  return extracted_count;
}

std::uint64_t derive_vm_bytecode_seed(const llvm::Function &function,
                                      const bytecode_program &program) {
  std::uint64_t seed = derive_vm_opaque_seed(function, program);
  seed = mix_seed(seed, 0x6eed0e9da4d94a4fULL);
  return seed == 0 ? 0x4f1bbcdc6762d5f1ULL : seed;
}

virtualization_result run_virtualization(llvm::Function &function,
                                         const virtualization_options &options) {
  bytecode_program program;
  const candidate_result analysis = analyze_candidate(function, &program);
  if (!analysis.eligible) {
    return {.virtualized = false, .detail = analysis.detail};
  }

  rewrite_function_body(function, program, options);
  return {.virtualized = true,
          .instruction_count = analysis.instruction_count,
          .detail = std::to_string(analysis.instruction_count) +
                    " virtual instruction(s) emitted"};
}

} // namespace obf::vm
