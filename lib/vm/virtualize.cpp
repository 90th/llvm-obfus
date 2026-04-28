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

  const std::uint64_t opaque_seed_base = derive_vm_opaque_seed(function, program);
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
