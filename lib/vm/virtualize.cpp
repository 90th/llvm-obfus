#include "obf/vm/virtualize_internal.h"

#include "obf/vm/internal/virtualize_anchor_scattering.h"

#include "obf/support/generated_names.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/StringExtras.h"
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
  if (attribute.isStringAttribute()) { return true; }

  if (!attribute.hasKindAsEnum()) { return false; }

  if (llvm::Attribute::intersectMustPreserve(attribute.getKindAsEnum())) { return true; }

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

llvm::AttributeList build_preserved_function_attributes(llvm::Function& function) {
  llvm::LLVMContext& context = function.getContext();
  const llvm::AttributeList original = function.getAttributes();
  llvm::AttributeList preserved;

  for (llvm::Attribute attribute : original.getRetAttrs()) {
    preserved = preserved.addRetAttribute(context, attribute);
  }

  for (llvm::Argument& argument : function.args()) {
    const unsigned argument_index = argument.getArgNo();
    for (llvm::Attribute attribute : original.getParamAttrs(argument_index)) {
      preserved = preserved.addAttributeAtIndex(
          context, llvm::AttributeList::FirstArgIndex + argument_index, attribute);
    }
  }

  for (llvm::Attribute attribute : original.getFnAttrs()) {
    if (should_preserve_function_attribute(attribute)) {
      if (attribute.isStringAttribute()) {
        preserved = preserved.addFnAttribute(
            context, attribute.getKindAsString(), attribute.getValueAsString());
        continue;
      }

      preserved = preserved.addFnAttribute(context, attribute);
    }
  }

  return preserved;
}


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

enum class vm_body_layout_shape {
  logical = 0,
  permuted = 1,
  family = 2,
};

enum class vm_status_trap_shape {
  direct = 0,
  twohop = 1,
  slot = 2,
};

enum class vm_terminal_trap_shape {
  direct = 0,
  twohop = 1,
  gated = 2,
};

template <typename Shape>
Shape select_vm_body_shape_variant(const llvm::Function& function,
                                   std::uint64_t bytecode_seed,
                                   std::uint64_t detail,
                                   std::uint64_t salt,
                                   std::uint32_t variant_count) {
  const std::uint64_t shape_seed = mix_seed(
      bytecode_seed ^ stable_hash_string(function.getName()), salt ^ detail ^ (detail << 7));
  return static_cast<Shape>(shape_seed % variant_count);
}

vm_body_layout_shape select_vm_body_layout_shape(const llvm::Function& function,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t detail,
                                                 std::size_t instruction_count) {
  if (instruction_count < 2) { return vm_body_layout_shape::logical; }
  if (instruction_count < 4) {
    return static_cast<vm_body_layout_shape>(
        1U + (mix_seed(bytecode_seed, 0x521500ULL ^ detail) % 2ULL));
  }
  return select_vm_body_shape_variant<vm_body_layout_shape>(
      function, bytecode_seed, detail, 0x521500ULL, 3U);
}

vm_status_trap_shape select_vm_status_trap_shape(const llvm::Function& function,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t detail) {
  return select_vm_body_shape_variant<vm_status_trap_shape>(
      function, bytecode_seed, detail, 0x521700ULL, 3U);
}

vm_terminal_trap_shape select_vm_terminal_trap_shape(const llvm::Function& function,
                                                     std::uint64_t bytecode_seed,
                                                     std::uint64_t detail) {
  return select_vm_body_shape_variant<vm_terminal_trap_shape>(
      function, bytecode_seed, detail, 0x521800ULL, 3U);
}

llvm::StringRef vm_body_layout_shape_marker(vm_body_layout_shape shape) {
  switch (shape) {
    case vm_body_layout_shape::logical:
      return "vm.body.layout.logical";
    case vm_body_layout_shape::permuted:
      return "vm.body.layout.permuted";
    case vm_body_layout_shape::family:
      return "vm.body.layout.family";
  }
  llvm_unreachable("unsupported vm body layout shape");
}

llvm::StringRef vm_status_trap_shape_marker(vm_status_trap_shape shape) {
  switch (shape) {
    case vm_status_trap_shape::direct:
      return "vm.trap.shape.direct";
    case vm_status_trap_shape::twohop:
      return "vm.trap.shape.twohop";
    case vm_status_trap_shape::slot:
      return "vm.trap.shape.slot";
  }
  llvm_unreachable("unsupported vm status trap shape");
}

llvm::StringRef vm_terminal_trap_shape_marker(vm_terminal_trap_shape shape) {
  switch (shape) {
    case vm_terminal_trap_shape::direct:
      return "vm.trap.shape.direct";
    case vm_terminal_trap_shape::twohop:
      return "vm.trap.shape.twohop";
    case vm_terminal_trap_shape::gated:
      return "vm.trap.shape.gated";
  }
  llvm_unreachable("unsupported vm terminal trap shape");
}

void note_vm_function_marker(llvm::Function& function, llvm::StringRef marker) {
  if (!function.hasFnAttribute(marker)) { function.addFnAttr(marker); }
}

llvm::SmallVector<std::size_t, 32>
build_vm_instruction_emission_order(const bytecode_program& program,
                                    llvm::ArrayRef<std::size_t> instruction_indices,
                                    std::uint64_t bytecode_seed,
                                    vm_body_layout_shape shape,
                                    std::uint64_t salt) {
  llvm::SmallVector<std::size_t, 32> order(instruction_indices.begin(), instruction_indices.end());
  if (order.size() < 2 || shape == vm_body_layout_shape::logical) { return order; }

  std::stable_sort(order.begin(), order.end(), [&](std::size_t lhs, std::size_t rhs) {
    if (shape == vm_body_layout_shape::family) {
      const std::uint64_t lhs_family =
          mix_seed(bytecode_seed, salt ^ (0x51573000ULL + opcode_family(program.instructions[lhs].op)));
      const std::uint64_t rhs_family =
          mix_seed(bytecode_seed, salt ^ (0x51573000ULL + opcode_family(program.instructions[rhs].op)));
      if (lhs_family != rhs_family) { return lhs_family < rhs_family; }
    }

    const std::uint64_t lhs_key = mix_seed(bytecode_seed, salt ^ (0x51573100ULL + lhs));
    const std::uint64_t rhs_key = mix_seed(bytecode_seed, salt ^ (0x51573100ULL + rhs));
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });
  return order;
}

llvm::SmallVector<std::uint32_t, 8>
build_vm_index_emission_order(std::uint32_t count,
                              std::uint64_t bytecode_seed,
                              vm_body_layout_shape shape,
                              std::uint64_t salt) {
  llvm::SmallVector<std::uint32_t, 8> order;
  order.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) { order.push_back(index); }
  if (order.size() < 2 || shape == vm_body_layout_shape::logical) { return order; }

  std::stable_sort(order.begin(), order.end(), [&](std::uint32_t lhs, std::uint32_t rhs) {
    if (shape == vm_body_layout_shape::family) {
      const std::uint64_t lhs_group = mix_seed(bytecode_seed, salt ^ (0x51573200ULL + (lhs & 1U)));
      const std::uint64_t rhs_group = mix_seed(bytecode_seed, salt ^ (0x51573200ULL + (rhs & 1U)));
      if (lhs_group != rhs_group) { return lhs_group < rhs_group; }
    }

    const std::uint64_t lhs_key = mix_seed(bytecode_seed, salt ^ (0x51573300ULL + lhs));
    const std::uint64_t rhs_key = mix_seed(bytecode_seed, salt ^ (0x51573300ULL + rhs));
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });
  return order;
}

void emit_vm_status_trap(llvm::Function& function,
                         llvm::BasicBlock* trap_block,
                         std::uint64_t bytecode_seed,
                         std::uint32_t choreography_detail,
                         std::uint64_t choreography_salt,
                         vm_status_trap_shape shape) {
  note_vm_function_marker(function, vm_status_trap_shape_marker(shape));

  auto build_status = [&](llvm::IRBuilder<>& builder) {
    return apply_vm_island_status_choreography(builder,
                                               function,
                                               bytecode_seed,
                                               builder.getInt32(vm_island_trap_status),
                                               choreography_detail,
                                               choreography_salt);
  };

  switch (shape) {
    case vm_status_trap_shape::direct: {
      llvm::IRBuilder<> trap_builder(trap_block);
      trap_builder.CreateRet(build_status(trap_builder));
      return;
    }
    case vm_status_trap_shape::twohop: {
      llvm::BasicBlock* trap_body = llvm::BasicBlock::Create(
          function.getContext(), trap_block->getName().str() + ".body", &function);
      llvm::IRBuilder<> trap_builder(trap_block);
      trap_builder.CreateBr(trap_body);
      llvm::IRBuilder<> body_builder(trap_body);
      body_builder.CreateRet(build_status(body_builder));
      return;
    }
    case vm_status_trap_shape::slot: {
      llvm::IRBuilder<> trap_builder(trap_block);
      auto* trap_status_slot =
          trap_builder.CreateAlloca(trap_builder.getInt32Ty(), nullptr, "vm.trap.status.slot");
      trap_builder.CreateStore(build_status(trap_builder), trap_status_slot);
      trap_builder.CreateRet(trap_builder.CreateLoad(
          trap_builder.getInt32Ty(), trap_status_slot, "vm.trap.status.ret"));
      return;
    }
  }

  llvm_unreachable("unsupported vm status trap shape");
}

void emit_vm_terminal_trap(llvm::Function& function,
                           llvm::BasicBlock* trap_block,
                           const mba::builder_context& mba_context,
                           std::uint64_t salt,
                           vm_terminal_trap_shape shape) {
  note_vm_function_marker(function, vm_terminal_trap_shape_marker(shape));

  llvm::FunctionCallee trap =
      llvm::Intrinsic::getOrInsertDeclaration(function.getParent(), llvm::Intrinsic::trap);
  switch (shape) {
    case vm_terminal_trap_shape::direct: {
      llvm::IRBuilder<> trap_builder(trap_block);
      trap_builder.CreateCall(trap);
      trap_builder.CreateUnreachable();
      return;
    }
    case vm_terminal_trap_shape::twohop: {
      llvm::BasicBlock* trap_body = llvm::BasicBlock::Create(
          function.getContext(), trap_block->getName().str() + ".body", &function);
      llvm::IRBuilder<> trap_builder(trap_block);
      trap_builder.CreateBr(trap_body);
      llvm::IRBuilder<> body_builder(trap_body);
      body_builder.CreateCall(trap);
      body_builder.CreateUnreachable();
      return;
    }
    case vm_terminal_trap_shape::gated: {
      llvm::BasicBlock* trap_body = llvm::BasicBlock::Create(
          function.getContext(), trap_block->getName().str() + ".body", &function);
      llvm::BasicBlock* trap_tail = llvm::BasicBlock::Create(
          function.getContext(), trap_block->getName().str() + ".tail", &function);
      llvm::IRBuilder<> trap_builder(trap_block);
      llvm::Value* gate_lhs = mba::create_opaque_integer(trap_builder,
                                                         trap_builder.getInt64Ty(),
                                                         mba_context,
                                                         llvm::APInt(64, 1),
                                                         salt ^ 0x11ULL,
                                                         "vm.trap.gate.lhs");
      llvm::Value* gate_rhs = mba::create_opaque_integer(trap_builder,
                                                         trap_builder.getInt64Ty(),
                                                         mba_context,
                                                         llvm::APInt(64, 1),
                                                         salt ^ 0x22ULL,
                                                         "vm.trap.gate.rhs");
      llvm::Value* trap_gate =
          trap_builder.CreateICmpEQ(gate_lhs, gate_rhs, "vm.trap.gate");
      trap_builder.CreateCondBr(trap_gate, trap_body, trap_tail);

      llvm::IRBuilder<> tail_builder(trap_tail);
      tail_builder.CreateBr(trap_body);

      llvm::IRBuilder<> body_builder(trap_body);
      body_builder.CreateCall(trap);
      body_builder.CreateUnreachable();
      return;
    }
  }

  llvm_unreachable("unsupported vm terminal trap shape");
}

struct subisland_plan {
  std::vector<std::uint32_t> subhelper_for_instruction;
  llvm::SmallVector<llvm::SmallVector<std::size_t, 16>, 8> instructions;
  llvm::SmallVector<std::uint32_t, 8> route_order;
  bool capped = false;
  bool enabled() const { return instructions.size() >= 2; }
};

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


llvm::BasicBlock* create_handler_success_route(rewrite_function_context& rewrite_context,
                                               llvm::BasicBlock* handler_block,
                                               std::size_t instruction_index) {
  llvm::Function& function = rewrite_context.function;
  function.addFnAttr("vm.handler.route.trampoline");
  auto* route_block = llvm::BasicBlock::Create(function.getContext(),
                                               "obf.vm.route.entry." +
                                                   std::to_string(instruction_index),
                                               &function,
                                               handler_block);
  llvm::IRBuilder<> route_builder(route_block);
  route_builder.CreateBr(handler_block);
  return route_block;
}

void emit_state_instruction_dispatcher(llvm::Function& dispatcher,
                                       const bytecode_program& program,
                                       const virtualization_options& options,
                                       const vm_state_layout& state_layout,
                                       llvm::GlobalVariable* bytecode_global,
                                       llvm::GlobalVariable* retkey_global,
                                       const std::vector<slot_cell_mapping>& slot_mappings,
                                       llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                                       const serialized_bytecode_program& serialized,
                                       const opcode_permutation& opcode_map,
                                       std::uint64_t opaque_seed_base,
                                       std::uint64_t bytecode_seed,
                                       llvm::ArrayRef<std::uint32_t> island_for_instruction,
                                       std::uint32_t island_index,
                                       std::uint32_t subhelper_index,
                                       llvm::ArrayRef<std::size_t> owned_instructions,
                                       bool subhelper) {
  llvm::LLVMContext& context = dispatcher.getContext();
  llvm::Module* module = dispatcher.getParent();
                      const std::uint64_t body_detail =
                        (static_cast<std::uint64_t>(island_index) << 32) | static_cast<std::uint64_t>(subhelper_index);
                      const vm_body_layout_shape body_layout_shape =
                        select_vm_body_layout_shape(dispatcher, bytecode_seed, body_detail, owned_instructions.size());
                      const vm_status_trap_shape trap_shape =
                        select_vm_status_trap_shape(dispatcher, bytecode_seed, body_detail);
                      note_vm_function_marker(dispatcher, vm_body_layout_shape_marker(body_layout_shape));
                      const llvm::SmallVector<std::size_t, 32> emission_order =
                        build_vm_instruction_emission_order(program,
                                          owned_instructions,
                                          bytecode_seed,
                                          body_layout_shape,
                                          0x521050ULL ^ body_detail);
  const std::string route_prefix = subhelper ? "vm.island.subhelper." : "vm.island.";
  const std::string entry_name = route_prefix + "entry." + std::to_string(island_index) + "." +
                                 std::to_string(subhelper_index);
  const std::string trap_name =
      route_prefix + "trap." + std::to_string(island_index) + "." + std::to_string(subhelper_index);
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(context, entry_name, &dispatcher);
  llvm::BasicBlock* dispatch_block =
      llvm::BasicBlock::Create(context,
                               route_prefix + "dispatch." + std::to_string(island_index) + "." +
                                   std::to_string(subhelper_index),
                               &dispatcher);
  llvm::BasicBlock* trap_block = llvm::BasicBlock::Create(context, trap_name, &dispatcher);
  llvm::BasicBlock* failure_block =
      llvm::BasicBlock::Create(context,
                               route_prefix + "fail.shared." + std::to_string(island_index) + "." +
                                   std::to_string(subhelper_index),
                               &dispatcher);

  llvm::IRBuilder<> entry_builder(entry_block);
  llvm::Argument* state_arg = &*dispatcher.arg_begin();
  state_arg->setName(subhelper ? "vm.island.subhelper.state" : "vm.island.state");
  slot_storage helper_slots =
      build_state_slot_storage(entry_builder, state_layout, state_arg, program, "vm.island.state");
  llvm::Value* state_slot = create_state_field_ptr(entry_builder,
                                                   state_layout,
                                                   state_arg,
                                                   state_layout.bytecode_state_field,
                                                   "vm.island.state.bc");
  llvm::Value* dispatch_index_slot = create_state_field_ptr(entry_builder,
                                                            state_layout,
                                                            state_arg,
                                                            state_layout.dispatch_index_field,
                                                            "vm.island.state.dispatch");
  llvm::Value* island_id_slot = create_state_field_ptr(entry_builder,
                                                       state_layout,
                                                       state_arg,
                                                       state_layout.island_id_field,
                                                       "vm.island.state.island");
  llvm::Value* hidden_token_slot = create_state_field_ptr(entry_builder,
                                                          state_layout,
                                                          state_arg,
                                                          state_layout.hidden_token_field,
                                                          "vm.island.state.token");
  llvm::Value* return_value_slot = nullptr;
  if (state_layout.return_value_field != invalid_slot) {
    return_value_slot = create_state_field_ptr(entry_builder,
                                               state_layout,
                                               state_arg,
                                               state_layout.return_value_field,
                                               "vm.island.state.ret");
  }
  llvm::AllocaInst* opcode_predicate_slot = entry_builder.CreateAlloca(
      entry_builder.getInt32Ty(), nullptr, "obf.vm.pred.slot");

  llvm::SmallVector<llvm::BasicBlock*, 64> instruction_blocks(program.instructions.size(), nullptr);
  for (std::size_t instruction_index : emission_order) {
    instruction_blocks[instruction_index] = llvm::BasicBlock::Create(
        context,
        route_prefix + std::to_string(island_index) + "." + std::to_string(subhelper_index) + "." +
            std::to_string(instruction_index),
        &dispatcher);
  }

  entry_builder.CreateBr(dispatch_block);

  llvm::IRBuilder<> dispatch_builder(dispatch_block);
  llvm::Value* initial_dispatch = dispatch_builder.CreateLoad(
      dispatch_builder.getInt32Ty(),
      dispatch_index_slot,
      subhelper ? "vm.island.subroute.dispatch" : "vm.island.helper.dispatch");
  initial_dispatch = apply_vm_helper_dispatch_choreography(
      dispatch_builder,
      dispatcher,
      bytecode_seed,
      initial_dispatch,
      owned_instructions.size(),
      0x521000ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
          static_cast<std::uint64_t>(subhelper_index));
  auto* entry_switch =
      dispatch_builder.CreateSwitch(initial_dispatch, failure_block, owned_instructions.size());

  const mba::builder_context mba_context{.entropy_anchor =
                                             mba::get_or_create_entropy_anchor(*module),
                                         .seed_base = opaque_seed_base,
                                         .depth = options.mba_depth,
                                         .max_ir_instructions_override =
                                             options.mba_max_ir_instructions,
                                         .enable_polynomial_override =
                                             options.mba_enable_polynomial,
                                         .enable_multiplication_override =
                                             options.mba_enable_multiplication};
    std::uint32_t bytecode_anchor_real_count = 0;
    std::uint32_t bytecode_anchor_decoy_count = 0;
    llvm::SmallVector<llvm::GlobalVariable*, 8> bytecode_anchor_globals =
      build_bytecode_anchor_globals(bytecode_global,
                    bytecode_seed,
                    0x273000ULL +
                      static_cast<std::uint64_t>(island_index) * 0x100ULL +
                      static_cast<std::uint64_t>(subhelper_index),
                    bytecode_anchor_real_count,
                    bytecode_anchor_decoy_count);
    annotate_bytecode_anchor_scattering(
      dispatcher, bytecode_anchor_real_count, bytecode_anchor_decoy_count);
  std::size_t dispatch_site_counter = 0;
  std::vector<switch_dispatch_bank> switch_dispatch_banks;
  const std::uint32_t island_count =
      island_for_instruction.empty()
          ? 0U
          : static_cast<std::uint32_t>(
                *std::max_element(island_for_instruction.begin(), island_for_instruction.end()) +
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
      .bytecode_anchor_globals = bytecode_anchor_globals,
      .bytecode_anchor_real_count = bytecode_anchor_real_count,
      .bytecode_anchor_decoy_count = bytecode_anchor_decoy_count,
      .retkey_global = retkey_global,
      .state_layout = &state_layout,
      .state_storage = state_arg,
      .state_slot = state_slot,
      .dispatch_index_slot = dispatch_index_slot,
      .island_id_slot = island_id_slot,
      .hidden_token_slot = hidden_token_slot,
      .return_value_slot = return_value_slot,
      .trap_block = failure_block,
      .opcode_predicate_slot = opcode_predicate_slot,
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
    llvm::BasicBlock* real_block = instruction_blocks[instruction_index];
    auto* guard_block = llvm::BasicBlock::Create(
        context,
        route_prefix + "guard." + std::to_string(island_index) + "." + std::to_string(subhelper_index) +
            "." + std::to_string(instruction_index),
        &dispatcher,
        real_block);
    const std::uint32_t decoy_island = island_for_instruction.empty()
                                           ? island_index
                                           : (island_index + 1) % island_count;
    const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(program,
                                                        dispatch_index_for_instruction,
                                                        island_for_instruction,
                                                        owned_instructions,
                                                        static_cast<std::uint32_t>(instruction_index),
                                                        decoy_island,
                                                        0x521020ULL +
                                                            static_cast<std::uint64_t>(island_index) * 0x1000ULL +
                                                            static_cast<std::uint64_t>(subhelper_index) * 0x100ULL +
                                                            instruction_index);
    llvm::ArrayRef<std::uint32_t> real_slot_mapping(slot_mappings[instruction_index]);
    llvm::ArrayRef<std::uint32_t> decoy_slot_mapping(slot_mappings[plan.decoy_instruction]);
    llvm::BasicBlock* decoy_block = EmitVmInlineDecoyBlock(
        dispatcher,
        rewrite_context,
        dispatch_block,
        real_slot_mapping,
        decoy_slot_mapping,
        plan,
        route_prefix + "decoy." + std::to_string(island_index) + "." +
            std::to_string(subhelper_index) + "." + std::to_string(instruction_index));
    entry_switch->addCase(dispatch_builder.getInt32(dispatch_index_for_instruction[instruction_index]),
                          guard_block);

    llvm::IRBuilder<> guard_builder(guard_block);
    llvm::Value* opaque_true = mba::build_entropy_true_predicate(guard_builder,
                                                                 dispatcher,
                                                                 std::max<std::uint32_t>(2, options.mba_depth),
                                                                 plan.salt,
                                                                 plan.salt ^ 0x11ULL,
                                                                 plan.salt ^ 0x22ULL,
                                                                 "obf.vm.decoy.helper.ctx.a",
                                                                 "obf.vm.decoy.helper.ctx.b",
                                                                 "obf.vm.decoy.helper.true");
    guard_builder.CreateCondBr(opaque_true, real_block, decoy_block);
  }

  for (std::size_t instruction_index : emission_order) {
    const micro_instruction& instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> header_builder(instruction_blocks[instruction_index]);
    const bytecode_layout& layout = serialized.layouts[instruction_index];
    instruction_rewrite_context instruction_context{
        .function_context = rewrite_context,
        .instruction_index = instruction_index,
        .instruction = instruction,
        .layout = layout,
        .current_slot_mapping = llvm::ArrayRef<std::uint32_t>(slot_mappings[instruction_index]),
    };

    llvm::Value* decoded_opcode =
        consume_metadata(header_builder,
                         rewrite_context,
                         layout,
                         0x8000 + static_cast<std::uint64_t>(instruction_index) * 32);
    decoded_opcode->setName(subhelper ? "vm.island.subhelper.decode" : "vm.island.helper.decode");

    emit_instruction_integrity_probes(header_builder, instruction_context);

    auto* opcode_block = llvm::BasicBlock::Create(
        context,
        route_prefix + "exec." + std::to_string(island_index) + "." +
            std::to_string(subhelper_index) + "." + std::to_string(instruction_index),
        &dispatcher);
    llvm::BasicBlock* route_block =
        create_handler_success_route(rewrite_context, opcode_block, instruction_index);
    llvm::Value* opcode_match = emit_opcode_match(header_builder,
                                                   rewrite_context,
                                                   decoded_opcode,
                                                  instruction.op,
                                                  0x7d000 + instruction_index);
    if (select_handler_variant(instruction.op, opaque_seed_base, 0x7d000 + instruction_index) ==
        0) {
      header_builder.CreateCondBr(opcode_match, route_block, failure_block);
    } else {
      llvm::Value* match_word = header_builder.CreateZExt(
          opcode_match, header_builder.getInt64Ty(), "obf.vm.opcode.match.word");
      llvm::Value* gated_match =
          mba::create_xor(header_builder,
                          match_word,
                          mba::create_opaque_integer(header_builder,
                                                     header_builder.getInt64Ty(),
                                                     mba_context,
                                                     llvm::APInt(64, 0),
                                                     0x7e000 + instruction_index,
                                                     "obf.vm.opcode.zero"),
                          mba_context,
                          0x7f000 + instruction_index,
                          "obf.vm.opcode.gate");
      llvm::Value* accept = header_builder.CreateICmpNE(
          gated_match, header_builder.getInt64(0), "obf.vm.opcode.accept");
      header_builder.CreateCondBr(accept, route_block, failure_block);
    }

    llvm::IRBuilder<> builder(opcode_block);
    if (lower_scalar_instruction(builder, instruction_context)) { continue; }
    if (lower_memory_instruction(builder, instruction_context)) { continue; }
    if (lower_control_instruction(builder, instruction_context)) { continue; }

    llvm_unreachable("unsupported vm opcode during island rewrite");
  }

  llvm::IRBuilder<> failure_builder(failure_block);
  failure_builder.CreateBr(trap_block);

    emit_vm_status_trap(dispatcher,
              trap_block,
              bytecode_seed,
              island_index,
              0x521100ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
                static_cast<std::uint64_t>(subhelper_index),
              trap_shape);
}

void emit_split_state_island_router(llvm::Function& helper,
                                    const vm_state_layout& state_layout,
                                    std::uint64_t bytecode_seed,
                                    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                                    llvm::ArrayRef<std::uint32_t> route_order,
                                    const subisland_plan& plan,
                                    llvm::ArrayRef<llvm::Function*> subhelpers,
                                    std::uint32_t island_index) {
  llvm::LLVMContext& context = helper.getContext();
  const vm_status_trap_shape trap_shape =
      select_vm_status_trap_shape(helper, bytecode_seed, 0x521210ULL + island_index);
  llvm::BasicBlock* entry_block = llvm::BasicBlock::Create(
      context, "vm.island.subroute.entry." + std::to_string(island_index), &helper);
  llvm::BasicBlock* trap_block = llvm::BasicBlock::Create(
      context, "vm.island.subroute.trap." + std::to_string(island_index), &helper);
  llvm::BasicBlock* failure_block = llvm::BasicBlock::Create(
      context, "vm.island.subroute.fail.shared." + std::to_string(island_index), &helper);
  llvm::IRBuilder<> entry_builder(entry_block);
  llvm::Argument* state_arg = &*helper.arg_begin();
  state_arg->setName("vm.island.state");
  llvm::Value* dispatch_index_slot = create_state_field_ptr(entry_builder,
                                                            state_layout,
                                                            state_arg,
                                                            state_layout.dispatch_index_field,
                                                            "vm.island.state.dispatch");
  llvm::Value* initial_dispatch = entry_builder.CreateLoad(
      entry_builder.getInt32Ty(), dispatch_index_slot, "vm.island.subroute");
  initial_dispatch = apply_vm_helper_dispatch_choreography(entry_builder,
                                                           helper,
                                                           bytecode_seed,
                                                           initial_dispatch,
                                                           plan.subhelper_for_instruction.size(),
                                                           0x521200ULL + island_index);
  auto* route_switch = entry_builder.CreateSwitch(
      initial_dispatch, failure_block, plan.subhelper_for_instruction.size());

  for (std::uint32_t subhelper_index : route_order) {
    auto* call_block =
        llvm::BasicBlock::Create(context,
                                 "vm.island.subroute.call." + std::to_string(island_index) + "." +
                                     std::to_string(subhelper_index),
                                 &helper);
    for (std::size_t instruction_index : plan.instructions[subhelper_index]) {
      route_switch->addCase(
          entry_builder.getInt32(dispatch_index_for_instruction[instruction_index]), call_block);
    }

    llvm::IRBuilder<> call_builder(call_block);
    auto* status = call_builder.CreateCall(subhelpers[subhelper_index]->getFunctionType(),
                                           subhelpers[subhelper_index],
                                           {state_arg},
                                           "vm.island.subroute.status");
    call_builder.CreateRet(apply_vm_island_status_choreography(
        call_builder,
        helper,
        bytecode_seed,
        status,
        subhelper_index,
        0x521300ULL + static_cast<std::uint64_t>(island_index) * 0x100ULL +
            static_cast<std::uint64_t>(subhelper_index)));
  }

  llvm::IRBuilder<> failure_builder(failure_block);
  failure_builder.CreateBr(trap_block);

    emit_vm_status_trap(
      helper, trap_block, bytecode_seed, island_index, 0x521400ULL + island_index, trap_shape);
}

void emit_state_island_helper(llvm::Function& helper,
                              const bytecode_program& program,
                              const virtualization_options& options,
                              const vm_state_layout& state_layout,
                              llvm::GlobalVariable* bytecode_global,
                              llvm::GlobalVariable* retkey_global,
                              const std::vector<slot_cell_mapping>& slot_mappings,
                              llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                              llvm::ArrayRef<std::uint64_t> entry_states,
                              const serialized_bytecode_program& serialized,
                              const opcode_permutation& opcode_map,
                              std::uint64_t opaque_seed_base,
                              std::uint64_t bytecode_seed,
                              llvm::Argument* hidden_token_arg,
                              llvm::ArrayRef<std::uint32_t> island_for_instruction,
                              std::uint32_t island_index) {
  (void)entry_states;
  (void)hidden_token_arg;

  const llvm::SmallVector<std::size_t, 32> owned_instructions =
      collect_island_instruction_indices(program, island_for_instruction, island_index);
  subisland_plan split_plan =
      build_subisland_plan(program, serialized, owned_instructions, bytecode_seed, island_index);
  if (!split_plan.enabled()) {
    emit_state_instruction_dispatcher(helper,
                                      program,
                                      options,
                                      state_layout,
                                      bytecode_global,
                                      retkey_global,
                                      slot_mappings,
                                      dispatch_index_for_instruction,
                                      serialized,
                                      opcode_map,
                                      opaque_seed_base,
                                      bytecode_seed,
                                      island_for_instruction,
                                      island_index,
                                      0,
                                      owned_instructions,
                                      false);
    return;
  }

  helper.addFnAttr("vm.island.helper.split");
  helper.addFnAttr("vm.island.helper.large");
  helper.addFnAttr("vm.island.subroute");
  if (split_plan.capped) { helper.addFnAttr("vm.island.helper.cap"); }

  llvm::LLVMContext& context = helper.getContext();
  llvm::Module* module = helper.getParent();
  auto* state_pointer_type = llvm::PointerType::get(context, 0);
  auto* helper_type =
      llvm::FunctionType::get(llvm::Type::getInt32Ty(context), {state_pointer_type}, false);
  llvm::SmallVector<llvm::Function*, 8> subhelpers;
  subhelpers.resize(split_plan.instructions.size(), nullptr);
    const vm_body_layout_shape subhelper_layout_shape = select_vm_body_layout_shape(
      helper, bytecode_seed, 0x521240ULL + island_index, split_plan.instructions.size());
    const llvm::SmallVector<std::uint32_t, 8> subhelper_emission_order =
      build_vm_index_emission_order(split_plan.instructions.size(),
                    bytecode_seed,
                    subhelper_layout_shape,
                    0x521250ULL + island_index);

    for (std::uint32_t subhelper_index : subhelper_emission_order) {
    llvm::Function* subhelper = llvm::Function::Create(
        helper_type,
        llvm::GlobalValue::InternalLinkage,
        make_vm_subisland_helper_name(*module, bytecode_seed, island_index, subhelper_index),
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

  emit_split_state_island_router(helper,
                                 state_layout,
                                 bytecode_seed,
                                 dispatch_index_for_instruction,
                                 split_plan.route_order,
                                 split_plan,
                                 subhelpers,
                                 island_index);

  for (std::uint32_t subhelper_index : subhelper_emission_order) {
    llvm::GlobalVariable* subhelper_bytecode =
        clone_bytecode_global_for_subhelper(bytecode_global, subhelper_index);
    emit_state_instruction_dispatcher(*subhelpers[subhelper_index],
                                      program,
                                      options,
                                      state_layout,
                                      subhelper_bytecode,
                                      retkey_global,
                                      slot_mappings,
                                      dispatch_index_for_instruction,
                                      serialized,
                                      opcode_map,
                                      opaque_seed_base,
                                      bytecode_seed,
                                      island_for_instruction,
                                      island_index,
                                      subhelper_index,
                                      split_plan.instructions[subhelper_index],
                                      true);
  }
}

void rewrite_function_body_state_islands(llvm::Function& function,
                                         const bytecode_program& program,
                                         const virtualization_options& options,
                                         llvm::StringRef symbol_tag,
                                         llvm::ArrayRef<llvm::BasicBlock*> old_blocks,
                                         std::uint64_t opaque_seed_base,
                                         std::uint64_t bytecode_seed,
                                         const opcode_permutation& opcode_map,
                                         std::uint32_t island_count) {
  for (llvm::BasicBlock* block : old_blocks) { block->dropAllReferences(); }
  for (llvm::BasicBlock* block : old_blocks) { block->eraseFromParent(); }

  llvm::LLVMContext& context = function.getContext();
  llvm::Module* module = function.getParent();
  auto* entry_block = llvm::BasicBlock::Create(context, "entry.obf.vm", &function);
  auto* route_block = llvm::BasicBlock::Create(context, "vm.island.route.entry", &function);
  auto* finish_block = llvm::BasicBlock::Create(context, "vm.island.done", &function);
  auto* trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);
  auto* failure_block = llvm::BasicBlock::Create(context, "obf.vm.fail.shared", &function);
  llvm::IRBuilder<> entry_builder(entry_block);

  vm_state_layout state_layout = build_vm_state_layout(context, function.getReturnType(), program);
  auto* state_storage = entry_builder.CreateAlloca(state_layout.type, nullptr, "vm.island.state");
  llvm::Value* state_slot = create_state_field_ptr(entry_builder,
                                                   state_layout,
                                                   state_storage,
                                                   state_layout.bytecode_state_field,
                                                   "vm.island.state.bc");
  llvm::Value* dispatch_index_slot = create_state_field_ptr(entry_builder,
                                                            state_layout,
                                                            state_storage,
                                                            state_layout.dispatch_index_field,
                                                            "vm.island.state.dispatch");
  llvm::Value* island_id_slot = create_state_field_ptr(entry_builder,
                                                       state_layout,
                                                       state_storage,
                                                       state_layout.island_id_field,
                                                       "vm.island.state.island");
  llvm::Value* hidden_token_slot = create_state_field_ptr(entry_builder,
                                                          state_layout,
                                                          state_storage,
                                                          state_layout.hidden_token_field,
                                                          "vm.island.state.token");
  llvm::Value* return_value_slot = nullptr;
  if (state_layout.return_value_field != invalid_slot) {
    return_value_slot = create_state_field_ptr(entry_builder,
                                               state_layout,
                                               state_storage,
                                               state_layout.return_value_field,
                                               "vm.island.state.ret");
    entry_builder.CreateStore(llvm::Constant::getNullValue(function.getReturnType()),
                              return_value_slot);
  }

  slot_storage state_slots = build_state_slot_storage(
      entry_builder, state_layout, state_storage, program, "vm.island.state");
  const std::vector<slot_cell_mapping> slot_mappings =
      build_slot_cell_mappings(program, opaque_seed_base);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed, dispatch_backend_variant::switch_index);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed, opcode_map);
  const std::vector<std::uint32_t> island_for_instruction =
      assign_vm_instruction_islands(program, bytecode_seed, island_count);

  llvm::SmallVector<llvm::GlobalVariable*, 8> bytecode_globals;
  bytecode_globals.resize(island_count, nullptr);
  if (!serialized.bytes.empty()) {
    auto* bytecode_type = llvm::ArrayType::get(entry_builder.getInt8Ty(), serialized.bytes.size());
    llvm::Constant* bytecode_initializer = llvm::ConstantDataArray::get(context, serialized.bytes);
    for (std::uint32_t island_index = 0; island_index < island_count; ++island_index) {
      llvm::GlobalVariable* bytecode_global = new llvm::GlobalVariable(
          *module,
          bytecode_type,
          true,
          llvm::GlobalValue::PrivateLinkage,
          bytecode_initializer,
          "__obf_vm_bc_" + symbol_tag.str() + "_s" + std::to_string(island_index));
      bytecode_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
      bytecode_globals[island_index] = bytecode_global;
    }
  }

  llvm::GlobalVariable* retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value = derive_vm_return_key(function, program);
    const std::string retkey_name = "__obf_vm_retkey_" + symbol_tag.str();
    retkey_global = module->getNamedGlobal(retkey_name);
    if (retkey_global == nullptr) {
      retkey_global = new llvm::GlobalVariable(*module,
                                               entry_builder.getInt64Ty(),
                                               false,
                                               llvm::GlobalValue::PrivateLinkage,
                                               entry_builder.getInt64(retkey_value),
                                               retkey_name);
    } else {
      retkey_global->setInitializer(entry_builder.getInt64(retkey_value));
      retkey_global->setConstant(false);
      retkey_global->setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  llvm::Argument* hidden_token_arg = nullptr;
  if (options.hidden_token_handshake && function.arg_size() > 0) {
    hidden_token_arg = &*std::prev(function.arg_end());
  }
  entry_builder.CreateStore(
      build_hidden_token_storage_value(entry_builder, hidden_token_arg, opaque_seed_base),
      hidden_token_slot);

  const std::uint32_t entry_instruction =
      program.blocks.empty() ? 0 : program.blocks.front().first_instruction;
  const slot_cell_mapping entry_identity_mapping(program.slots.size(), 0);
  llvm::ArrayRef<std::uint32_t> entry_slot_mapping = entry_identity_mapping;
  if (!slot_mappings.empty()) { entry_slot_mapping = slot_mappings[entry_instruction]; }

  const mba::builder_context mba_context{.entropy_anchor =
                                             mba::get_or_create_entropy_anchor(*module),
                                         .seed_base = opaque_seed_base,
                                         .depth = options.mba_depth,
                                         .max_ir_instructions_override =
                                             options.mba_max_ir_instructions,
                                         .enable_polynomial_override =
                                             options.mba_enable_polynomial,
                                         .enable_multiplication_override =
                                             options.mba_enable_multiplication};
  entry_builder.CreateStore(build_hidden_token_seed(entry_builder,
                                                    hidden_token_arg,
                                                    program.instructions.empty()
                                                        ? bytecode_seed
                                                        : entry_states[entry_instruction],
                                                    options.valid_hidden_tokens,
                                                    mba_context,
                                                    0x3100,
                                                    "obf.vm.token.state"),
                            state_slot);
  entry_builder.CreateStore(
      entry_builder.getInt32(dispatch_index_for_instruction[entry_instruction]),
      dispatch_index_slot);
  entry_builder.CreateStore(entry_builder.getInt32(island_for_instruction[entry_instruction]),
                            island_id_slot);

  std::size_t argument_index = 0;
  for (llvm::Argument& argument : function.args()) {
    store_slot(entry_builder,
               state_slots,
               entry_slot_mapping,
               program,
               program.argument_slots[argument_index],
               &argument,
               nullptr,
               opaque_seed_base,
               mba_context,
               0x8110 + argument_index);
    ++argument_index;
  }

    const vm_body_layout_shape root_layout_shape =
      select_vm_body_layout_shape(function, bytecode_seed, 0x521600ULL, island_count);
    const vm_terminal_trap_shape trap_shape =
      select_vm_terminal_trap_shape(function, bytecode_seed, 0x521610ULL + island_count);
    note_vm_function_marker(function, vm_body_layout_shape_marker(root_layout_shape));
    llvm::SmallVector<llvm::Function*, 8> helpers;
    llvm::SmallVector<llvm::Function*, 8> decoy_helpers;
    helpers.resize(island_count, nullptr);
    decoy_helpers.resize(island_count, nullptr);
  auto* state_pointer_type = llvm::PointerType::get(context, 0);
  auto* helper_type =
      llvm::FunctionType::get(entry_builder.getInt32Ty(), {state_pointer_type}, false);
    const llvm::SmallVector<std::uint32_t, 8> helper_emission_order =
      build_vm_index_emission_order(island_count,
                    bytecode_seed,
                    root_layout_shape,
                    0x521620ULL + island_count);
    for (std::uint32_t island_index : helper_emission_order) {
    llvm::Function* helper =
        llvm::Function::Create(helper_type,
                               llvm::GlobalValue::InternalLinkage,
                               make_vm_island_helper_name(*module, bytecode_seed, island_index),
                               module);
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
    helpers[island_index] = helper;

    llvm::Function* decoy_helper = llvm::Function::Create(helper_type,
                                                          llvm::GlobalValue::InternalLinkage,
                                                          MakeVmIslandDecoyHelperName(
                                                              *module, bytecode_seed, island_index),
                                                          module);
    decoy_helper->setDSOLocal(true);
    decoy_helper->addFnAttr(llvm::Attribute::NoInline);
    decoy_helper->addFnAttr("instcombine-no-verify-fixpoint");
    decoy_helper->addFnAttr("vm.island.helper");
    decoy_helper->addFnAttr("vm.island.helper.decoy");
    decoy_helper->addFnAttr("vm.island.state");
    decoy_helpers[island_index] = decoy_helper;
  }

  entry_builder.CreateBr(route_block);
  llvm::IRBuilder<> route_builder(route_block);
  auto* status_phi = route_builder.CreatePHI(
      route_builder.getInt32Ty(), helpers.size() + 1, "vm.island.route.status");
  status_phi->addIncoming(route_builder.getInt32(vm_island_continue_status), entry_block);
  auto* island_route_block = llvm::BasicBlock::Create(context, "vm.island.root.route", &function);
  auto* route_switch = route_builder.CreateSwitch(status_phi, failure_block, 3);
  route_switch->addCase(route_builder.getInt32(vm_island_continue_status), island_route_block);
  route_switch->addCase(route_builder.getInt32(vm_island_done_status), finish_block);
  route_switch->addCase(route_builder.getInt32(vm_island_trap_status), failure_block);

  llvm::IRBuilder<> island_route_builder(island_route_block);
  llvm::Value* current_island = island_route_builder.CreateLoad(
      island_route_builder.getInt32Ty(), island_id_slot, "vm.island.root.route");
  auto* island_switch =
      island_route_builder.CreateSwitch(current_island, failure_block, helpers.size());

  for (std::uint32_t island_index : helper_emission_order) {
    auto* guard_block = llvm::BasicBlock::Create(
        context, "vm.island.call.guard." + std::to_string(island_index), &function);
    auto* call_block = llvm::BasicBlock::Create(
        context, "vm.island.call." + std::to_string(island_index), &function);
    auto* decoy_call_block = llvm::BasicBlock::Create(
        context, "vm.island.call.decoy." + std::to_string(island_index), &function);
    island_switch->addCase(island_route_builder.getInt32(island_index), guard_block);

    const llvm::SmallVector<std::size_t, 32> owned_instructions =
        collect_island_instruction_indices(program, island_for_instruction, island_index);
    const std::uint32_t entry_instruction = owned_instructions.empty()
                                                ? 0
                                                : static_cast<std::uint32_t>(owned_instructions.front());
    const std::uint32_t decoy_island = (island_index + 1) % helpers.size();
    const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(program,
                                                        dispatch_index_for_instruction,
                                                        island_for_instruction,
                                                        owned_instructions,
                                                        entry_instruction,
                                                        decoy_island,
                                                        0x521680ULL + island_index);

    llvm::IRBuilder<> guard_builder(guard_block);
    llvm::Value* opaque_true = mba::build_entropy_true_predicate(guard_builder,
                                                                 function,
                                                                 std::max<std::uint32_t>(2, options.mba_depth),
                                                                 plan.salt,
                                                                 plan.salt ^ 0x11ULL,
                                                                 plan.salt ^ 0x22ULL,
                                                                 "obf.vm.decoy.root.ctx.a",
                                                                 "obf.vm.decoy.root.ctx.b",
                                                                 "obf.vm.decoy.root.true");
    guard_builder.CreateCondBr(opaque_true, call_block, decoy_call_block);

    llvm::IRBuilder<> call_builder(call_block);
    auto* status = call_builder.CreateCall(helpers[island_index]->getFunctionType(),
                                           helpers[island_index],
                                           {state_storage},
                                           "vm.island.status");
    call_builder.CreateBr(route_block);
    status_phi->addIncoming(status, call_block);

    llvm::IRBuilder<> decoy_call_builder(decoy_call_block);
    auto* decoy_status = decoy_call_builder.CreateCall(decoy_helpers[island_index]->getFunctionType(),
                                                       decoy_helpers[island_index],
                                                       {state_storage},
                                                       "vm.island.decoy.status");
    decoy_call_builder.CreateBr(route_block);
    status_phi->addIncoming(decoy_status, decoy_call_block);
  }

  llvm::IRBuilder<> finish_builder(finish_block);
  if (function.getReturnType()->isVoidTy()) {
    finish_builder.CreateRetVoid();
  } else {
    finish_builder.CreateRet(finish_builder.CreateLoad(
        function.getReturnType(), return_value_slot, "vm.island.root.finalize"));
  }

  llvm::IRBuilder<> failure_builder(failure_block);
  failure_builder.CreateBr(trap_block);

  emit_vm_terminal_trap(function, trap_block, mba_context, 0x521630ULL + island_count, trap_shape);

  for (std::uint32_t island_index : helper_emission_order) {
    emit_state_island_helper(*helpers[island_index],
                             program,
                             options,
                             state_layout,
                             bytecode_globals[island_index],
                             retkey_global,
                             slot_mappings,
                             dispatch_index_for_instruction,
                             entry_states,
                             serialized,
                             opcode_map,
                             opaque_seed_base,
                             bytecode_seed,
                             hidden_token_arg,
                             island_for_instruction,
                             island_index);

    const llvm::SmallVector<std::size_t, 32> owned_instructions =
        collect_island_instruction_indices(program, island_for_instruction, island_index);
    const std::uint32_t entry_instruction = owned_instructions.empty()
                                                ? 0
                                                : static_cast<std::uint32_t>(owned_instructions.front());
    const std::uint32_t decoy_island = (island_index + 1) % helpers.size();
    EmitVmDecoyHelperBody(*decoy_helpers[island_index],
                          program,
                          state_layout,
                          slot_mappings,
                          opaque_seed_base,
                          bytecode_seed,
                          options.mba_depth,
                          BuildVmDecoyRoutePlan(program,
                                                dispatch_index_for_instruction,
                                                island_for_instruction,
                                                owned_instructions,
                                                entry_instruction,
                                                decoy_island,
                                                0x521780ULL + island_index));
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

void rewrite_function_body(llvm::Function& function,
                           const bytecode_program& program,
                           const virtualization_options& options) {
  llvm::LLVMContext& context = function.getContext();
  const std::string symbol_tag =
      options.symbol_tag.empty() ? function.getName().str() : options.symbol_tag;
  const llvm::AttributeList preserved_attributes = build_preserved_function_attributes(function);

  function.setAttributes(preserved_attributes);
  function.addFnAttr("instcombine-no-verify-fixpoint");

  llvm::SmallVector<llvm::BasicBlock*, 8> old_blocks;
  old_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) { old_blocks.push_back(&block); }

  const std::uint64_t opaque_seed_base = derive_vm_opaque_seed(function, program);
  const std::uint64_t bytecode_seed = derive_vm_bytecode_seed(function, program);
  const opcode_permutation opcode_map = build_opcode_permutation(function, program);
  const vm_dispatcher_shape dispatch_shape = select_dispatcher_shape(
      bytecode_seed, opaque_seed_base ^ 0x26000ULL, program.instructions.size());
  const vm_island_topology island_topology =
      select_vm_island_topology(options.prefer_island_helpers,
                                program.instructions.size(),
                                bytecode_seed,
                                opaque_seed_base ^ 0x26003ULL);
  const std::uint32_t island_count = select_vm_island_count(
      bytecode_seed, opaque_seed_base ^ 0x26002ULL, program.instructions.size(), island_topology);

  if (should_use_state_islands(program, island_topology, island_count)) {
    rewrite_function_body_state_islands(function,
                                        program,
                                        options,
                                        symbol_tag,
                                        old_blocks,
                                        opaque_seed_base,
                                        bytecode_seed,
                                        opcode_map,
                                        island_count);
    return;
  }

  for (llvm::BasicBlock* block : old_blocks) { block->dropAllReferences(); }
  for (llvm::BasicBlock* block : old_blocks) { block->eraseFromParent(); }

  auto* entry_block = llvm::BasicBlock::Create(context, "entry.obf.vm", &function);
  auto* dispatch_loop_block =
      llvm::BasicBlock::Create(context, "vm.dispatch.loop", &function);
  auto* trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);
  auto* failure_block = llvm::BasicBlock::Create(context, "obf.vm.fail.shared", &function);

    const vm_body_layout_shape body_layout_shape =
      select_vm_body_layout_shape(function, bytecode_seed, 0x521900ULL, program.instructions.size());
    const vm_terminal_trap_shape trap_shape =
      select_vm_terminal_trap_shape(function, bytecode_seed, 0x521910ULL + program.instructions.size());
    note_vm_function_marker(function, vm_body_layout_shape_marker(body_layout_shape));
    llvm::SmallVector<std::size_t, 32> instruction_indices;
    instruction_indices.reserve(program.instructions.size());
    for (std::size_t instruction_index = 0; instruction_index < program.instructions.size();
       ++instruction_index) {
    instruction_indices.push_back(instruction_index);
    }
    const llvm::SmallVector<std::size_t, 32> instruction_emission_order =
      build_vm_instruction_emission_order(
        program, instruction_indices, bytecode_seed, body_layout_shape, 0x521920ULL);

    llvm::SmallVector<llvm::BasicBlock*, 32> instruction_blocks(program.instructions.size(), nullptr);
    for (std::size_t instruction_index : instruction_emission_order) {
    instruction_blocks[instruction_index] =
      llvm::BasicBlock::Create(context, "vm." + std::to_string(instruction_index), &function);
    }

  llvm::IRBuilder<> entry_builder(entry_block);
  vm_state_layout state_layout = build_vm_state_layout(context, function.getReturnType(), program);
  auto* state_storage = entry_builder.CreateAlloca(state_layout.type, nullptr, "obf.vm.state");
  slot_storage slot_allocas =
      build_state_slot_storage(entry_builder, state_layout, state_storage, program, "obf.vm.state");
  llvm::Value* state_slot = create_state_field_ptr(entry_builder,
                                                   state_layout,
                                                   state_storage,
                                                   state_layout.bytecode_state_field,
                                                   "obf.vm.state.bc");
  llvm::Value* dispatch_index_slot = create_state_field_ptr(entry_builder,
                                                            state_layout,
                                                            state_storage,
                                                            state_layout.dispatch_index_field,
                                                            "obf.vm.state.dispatch");
  llvm::Value* island_id_slot = create_state_field_ptr(entry_builder,
                                                       state_layout,
                                                       state_storage,
                                                       state_layout.island_id_field,
                                                       "obf.vm.state.island");
  llvm::Value* hidden_token_slot = create_state_field_ptr(entry_builder,
                                                          state_layout,
                                                          state_storage,
                                                          state_layout.hidden_token_field,
                                                          "obf.vm.state.token");
  llvm::Value* return_value_slot = nullptr;
  if (state_layout.return_value_field != invalid_slot) {
    return_value_slot = create_state_field_ptr(entry_builder,
                                               state_layout,
                                               state_storage,
                                               state_layout.return_value_field,
                                               "obf.vm.state.ret");
    entry_builder.CreateStore(llvm::Constant::getNullValue(function.getReturnType()),
                              return_value_slot);
  }

  const std::vector<slot_cell_mapping> slot_mappings =
      build_slot_cell_mappings(program, opaque_seed_base);
  llvm::AllocaInst* opaque_seed = nullptr;
  llvm::GlobalVariable* entropy_anchor = mba::get_or_create_entropy_anchor(*function.getParent());
  const mba::builder_context mba_context{
      .entropy_anchor = entropy_anchor,
      .seed_base = opaque_seed_base,
      .depth = options.mba_depth,
      .max_ir_instructions_override = options.mba_max_ir_instructions,
      .enable_polynomial_override = options.mba_enable_polynomial,
      .enable_multiplication_override = options.mba_enable_multiplication};

  llvm::Argument* hidden_token_arg = nullptr;
  if (options.hidden_token_handshake && function.arg_size() > 0) {
    hidden_token_arg = &*std::prev(function.arg_end());
  }

  dispatch_backend_variant dispatch_backend = dispatch_backend_variant::switch_index;
  vm_dispatcher_shape effective_dispatch_shape = dispatch_shape;
  if (island_topology == vm_island_topology::helper_shards) {
    effective_dispatch_shape = vm_dispatcher_shape::switch_biased;
  }
  if (effective_dispatch_shape == vm_dispatcher_shape::direct_threaded) {
    dispatch_backend = static_cast<dispatch_backend_variant>(select_dispatch_variant(
        bytecode_seed, opaque_seed_base ^ 0x26000ULL, program.instructions.size()));
    if (dispatch_backend == dispatch_backend_variant::switch_index) {
      dispatch_backend = dispatch_backend_variant::direct_threaded_match;
    }
  }
  const std::uint32_t switch_dispatch_bank_count =
      select_switch_dispatch_bank_count(bytecode_seed,
                                        opaque_seed_base ^ 0x26001ULL,
                                        program.instructions.size(),
                                        effective_dispatch_shape);
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed, dispatch_backend);
  const std::vector<std::uint32_t> island_for_instruction =
      assign_vm_instruction_islands(program, bytecode_seed, island_count);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed, opcode_map);

  llvm::GlobalVariable* bytecode_global = nullptr;
  if (!serialized.bytes.empty()) {
    auto* bytecode_type = llvm::ArrayType::get(entry_builder.getInt8Ty(), serialized.bytes.size());
    bytecode_global =
        new llvm::GlobalVariable(*function.getParent(),
                                 bytecode_type,
                                 true,
                                 llvm::GlobalValue::PrivateLinkage,
                                 llvm::ConstantDataArray::get(context, serialized.bytes),
                                 "__obf_vm_bc_" + symbol_tag);
    bytecode_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  }

  std::uint32_t bytecode_anchor_real_count = 0;
  std::uint32_t bytecode_anchor_decoy_count = 0;
  llvm::SmallVector<llvm::GlobalVariable*, 8> bytecode_anchor_globals =
      build_bytecode_anchor_globals(bytecode_global,
                                    bytecode_seed,
                                    0x272000ULL,
                                    bytecode_anchor_real_count,
                                    bytecode_anchor_decoy_count);
  annotate_bytecode_anchor_scattering(
      function, bytecode_anchor_real_count, bytecode_anchor_decoy_count);

  llvm::GlobalVariable* retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value = derive_vm_return_key(function, program);
    const std::string retkey_name = "__obf_vm_retkey_" + symbol_tag;
    retkey_global = function.getParent()->getNamedGlobal(retkey_name);
    if (retkey_global == nullptr) {
      retkey_global = new llvm::GlobalVariable(*function.getParent(),
                                               entry_builder.getInt64Ty(),
                                               /*isConstant=*/false,
                                               llvm::GlobalValue::PrivateLinkage,
                                               entry_builder.getInt64(retkey_value),
                                               retkey_name);
    } else {
      if (retkey_global->getValueType() != entry_builder.getInt64Ty()) {
        llvm_unreachable("vm retkey global has unexpected type");
      }
      retkey_global->setInitializer(entry_builder.getInt64(retkey_value));
      retkey_global->setConstant(false);
      retkey_global->setLinkage(llvm::GlobalValue::PrivateLinkage);
    }
  }

  auto* opcode_predicate_slot =
      entry_builder.CreateAlloca(entry_builder.getInt32Ty(), nullptr, "obf.vm.pred.slot");

  const std::uint32_t entry_instruction =
      program.blocks.empty() ? 0 : program.blocks.front().first_instruction;
  const slot_cell_mapping entry_identity_mapping(program.slots.size(), 0);
  llvm::ArrayRef<std::uint32_t> entry_slot_mapping = entry_identity_mapping;
  if (!slot_mappings.empty()) { entry_slot_mapping = slot_mappings[entry_instruction]; }
  entry_builder.CreateStore(
      build_hidden_token_storage_value(entry_builder, hidden_token_arg, opaque_seed_base),
      hidden_token_slot);
  (void)entry_builder.CreateStore(build_hidden_token_seed(entry_builder,
                                                          hidden_token_arg,
                                                          program.instructions.empty()
                                                              ? bytecode_seed
                                                              : entry_states[entry_instruction],
                                                          options.valid_hidden_tokens,
                                                          mba_context,
                                                          0x3100,
                                                          "obf.vm.token.state"),
                                  state_slot);
  entry_builder.CreateStore(entry_builder.getInt32(dispatch_index_for_instruction[entry_instruction]),
                            dispatch_index_slot);
  entry_builder.CreateStore(entry_builder.getInt32(program.instructions.empty()
                                                       ? 0
                                                       : island_for_instruction[entry_instruction]),
                            island_id_slot);

  llvm::AllocaInst* dispatch_table = nullptr;
  llvm::ArrayType* dispatch_table_type = nullptr;
  llvm::IntegerType* ptr_int_type = nullptr;
  if (!instruction_blocks.empty()) {
    const llvm::DataLayout& data_layout = function.getParent()->getDataLayout();
    ptr_int_type = data_layout.getIntPtrType(context, function.getAddressSpace());
  }
  if (!instruction_blocks.empty() && dispatch_backend != dispatch_backend_variant::switch_index) {
    dispatch_table_type = llvm::ArrayType::get(ptr_int_type, instruction_blocks.size());
    dispatch_table =
        entry_builder.CreateAlloca(dispatch_table_type, nullptr, "obf.vm.dispatch.table");
  }

  std::size_t argument_index = 0;
  for (llvm::Argument& argument : function.args()) {
    store_slot(entry_builder,
               slot_allocas,
               entry_slot_mapping,
               program,
               program.argument_slots[argument_index],
               &argument,
               opaque_seed,
               opaque_seed_base,
               mba_context,
               0x8110 + argument_index);
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
      .bytecode_anchor_globals = bytecode_anchor_globals,
      .bytecode_anchor_real_count = bytecode_anchor_real_count,
      .bytecode_anchor_decoy_count = bytecode_anchor_decoy_count,
      .retkey_global = retkey_global,
      .state_layout = &state_layout,
      .state_storage = state_storage,
      .state_slot = state_slot,
      .dispatch_index_slot = dispatch_index_slot,
      .island_id_slot = island_id_slot,
      .hidden_token_slot = hidden_token_slot,
      .return_value_slot = return_value_slot,
      .trap_block = failure_block,
      .opcode_predicate_slot = opcode_predicate_slot,
      .instruction_blocks = instruction_blocks,
      .island_for_instruction = island_for_instruction,
      .dispatch_table = dispatch_table,
      .dispatch_table_type = dispatch_table_type,
      .ptr_int_type = ptr_int_type,
      .switch_dispatch_banks = switch_dispatch_banks,
      .dispatch_site_counter = dispatch_site_counter,
  };

  initialize_dispatch_runtime(entry_builder, rewrite_context);

  if (dispatch_backend == dispatch_backend_variant::switch_index && instruction_blocks.size() > 1) {
    const std::uint32_t root_island_count = std::max<std::uint32_t>(1, island_count);
    for (std::size_t bank_position = 0; bank_position < switch_dispatch_banks.size(); ++bank_position) {
      switch_dispatch_bank& bank = switch_dispatch_banks[bank_position];
      if (bank.switch_inst == nullptr) { continue; }
      for (auto case_it = bank.switch_inst->case_begin(); case_it != bank.switch_inst->case_end();
           ++case_it) {
        llvm::BasicBlock* real_block = case_it->getCaseSuccessor();
        auto real_it = std::find(instruction_blocks.begin(), instruction_blocks.end(), real_block);
        if (real_it == instruction_blocks.end()) { continue; }

        const std::size_t instruction_index =
            static_cast<std::size_t>(real_it - instruction_blocks.begin());
        const std::uint32_t decoy_island =
            root_island_count <= 1
                ? 0
                : (island_for_instruction[instruction_index] + 1U) % root_island_count;
        const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(program,
                                                            dispatch_index_for_instruction,
                                                            island_for_instruction,
                                                            instruction_indices,
                                                            static_cast<std::uint32_t>(instruction_index),
                                                            decoy_island,
                                                            0x521a000ULL +
                                                                static_cast<std::uint64_t>(bank_position) * 0x1000ULL +
                                                                instruction_index);
        llvm::ArrayRef<std::uint32_t> real_slot_mapping(slot_mappings[instruction_index]);
        llvm::ArrayRef<std::uint32_t> decoy_slot_mapping(slot_mappings[plan.decoy_instruction]);
        auto* guard_block = llvm::BasicBlock::Create(
            context,
            "vm.dispatch.root.guard." + std::to_string(bank_position) + "." +
                std::to_string(instruction_index),
            &function,
            real_block);
        llvm::BasicBlock* decoy_block = EmitVmInlineDecoyBlock(
            function,
            rewrite_context,
            dispatch_loop_block,
            real_slot_mapping,
            decoy_slot_mapping,
            plan,
            "vm.dispatch.root.decoy." + std::to_string(bank_position) + "." +
                std::to_string(instruction_index));
        case_it->setSuccessor(guard_block);

        llvm::IRBuilder<> guard_builder(guard_block);
        llvm::Value* opaque_true = mba::build_entropy_true_predicate(guard_builder,
                                                                     function,
                                                                     std::max<std::uint32_t>(2,
                                                                                             options.mba_depth),
                                                                     plan.salt,
                                                                     plan.salt ^ 0x11ULL,
                                                                     plan.salt ^ 0x22ULL,
                                                                     "obf.vm.decoy.ctx.a",
                                                                     "obf.vm.decoy.ctx.b",
                                                                     "obf.vm.decoy.true");
        guard_builder.CreateCondBr(opaque_true, real_block, decoy_block);
      }
    }
  }

  if (instruction_blocks.empty()) {
    entry_builder.CreateBr(failure_block);
    llvm::IRBuilder<> dispatch_loop_builder(dispatch_loop_block);
    dispatch_loop_builder.CreateBr(failure_block);
  } else {
    entry_builder.CreateBr(dispatch_loop_block);
    llvm::IRBuilder<> dispatch_loop_builder(dispatch_loop_block);
    llvm::Value* initial_dispatch = dispatch_loop_builder.CreateLoad(
        dispatch_loop_builder.getInt32Ty(), dispatch_index_slot, "obf.vm.dispatch.loop.index");
    emit_dispatch(dispatch_loop_builder, rewrite_context, initial_dispatch, 0x3000);
  }

  for (std::size_t instruction_index : instruction_emission_order) {
    const micro_instruction& instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> header_builder(instruction_blocks[instruction_index]);
    const bytecode_layout& layout = serialized.layouts[instruction_index];
    instruction_rewrite_context instruction_context{
        .function_context = rewrite_context,
        .instruction_index = instruction_index,
        .instruction = instruction,
        .layout = layout,
        .current_slot_mapping = llvm::ArrayRef<std::uint32_t>(slot_mappings[instruction_index]),
    };

    llvm::Value* decoded_opcode =
        consume_metadata(header_builder,
                         rewrite_context,
                         layout,
                         0x8000 + static_cast<std::uint64_t>(instruction_index) * 32);

    emit_instruction_integrity_probes(header_builder, instruction_context);

    auto* opcode_block = llvm::BasicBlock::Create(
        context, "vm.exec." + std::to_string(instruction_index), &function);
    llvm::BasicBlock* route_block =
        create_handler_success_route(rewrite_context, opcode_block, instruction_index);
    llvm::Value* opcode_match = emit_opcode_match(header_builder,
                                                   rewrite_context,
                                                   decoded_opcode,
                                                  instruction.op,
                                                  0x7d000 + instruction_index);
    if (select_handler_variant(instruction.op, opaque_seed_base, 0x7d000 + instruction_index) ==
        0) {
      header_builder.CreateCondBr(opcode_match, route_block, failure_block);
    } else {
      llvm::Value* match_word = header_builder.CreateZExt(
          opcode_match, header_builder.getInt64Ty(), "obf.vm.opcode.match.word");
      llvm::Value* gated_match =
          mba::create_xor(header_builder,
                          match_word,
                          mba::create_opaque_integer(header_builder,
                                                     header_builder.getInt64Ty(),
                                                     mba_context,
                                                     llvm::APInt(64, 0),
                                                     0x7e000 + instruction_index,
                                                     "obf.vm.opcode.zero"),
                          mba_context,
                          0x7f000 + instruction_index,
                          "obf.vm.opcode.gate");
      llvm::Value* accept = header_builder.CreateICmpNE(
          gated_match, header_builder.getInt64(0), "obf.vm.opcode.accept");
      header_builder.CreateCondBr(accept, route_block, failure_block);
    }

    llvm::IRBuilder<> builder(opcode_block);
    if (lower_scalar_instruction(builder, instruction_context)) { continue; }
    if (lower_memory_instruction(builder, instruction_context)) { continue; }
    if (lower_control_instruction(builder, instruction_context)) { continue; }

    llvm_unreachable("unsupported vm opcode during rewrite");
  }

  outline_vm_islands(rewrite_context);

  llvm::IRBuilder<> failure_builder(failure_block);
  failure_builder.CreateBr(trap_block);

  emit_vm_terminal_trap(function,
                        trap_block,
                        mba_context,
                        0x521930ULL + program.instructions.size(),
                        trap_shape);
}

}  // namespace

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

virtualization_result run_virtualization(llvm::Function& function,
                                         const virtualization_options& options) {
  bytecode_program program;
  const candidate_result analysis = analyze_candidate(function, &program);
  if (!analysis.eligible) { return {.virtualized = false, .detail = analysis.detail}; }

  rewrite_function_body(function, program, options);
  return {.virtualized = true,
          .instruction_count = analysis.instruction_count,
          .detail = std::to_string(analysis.instruction_count) + " virtual instruction(s) emitted"};
}

}  // namespace obf::vm
