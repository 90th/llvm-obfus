#include "obf/vm/internal/virtualize_body_rewrite.h"
#include "obf/vm/internal/virtualize_dispatch_return.h"
#include "obf/vm/internal/virtualize_island_topology.h"
#include "obf/vm/internal/virtualize_anchor_scattering.h"
#include "obf/vm/virtualize_internal.h"

#include "obf/support/generated_names.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <numeric>
#include <string>
#include <vector>

namespace obf::vm {

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

  const std::uint64_t opaque_seed_base =
      derive_vm_opaque_seed(options.decision_seed, function, program);
  const std::uint64_t bytecode_seed =
      derive_vm_bytecode_seed(options.decision_seed, function, program);
  const opcode_permutation opcode_map = build_opcode_permutation(function, program, bytecode_seed);
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
  auto* dispatch_loop_block = llvm::BasicBlock::Create(context, "vm.dispatch.loop", &function);
  auto* trap_block = llvm::BasicBlock::Create(context, "trap.obf.vm", &function);
  auto* failure_block = llvm::BasicBlock::Create(context, "obf.vm.fail.shared", &function);

  const vm_body_layout_shape body_layout_shape = select_vm_body_layout_shape(
      function, bytecode_seed, 0x521900ULL, program.instructions.size());
  const vm_terminal_trap_shape trap_shape = select_vm_terminal_trap_shape(
      function, bytecode_seed, 0x521910ULL + program.instructions.size());
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
    const std::uint64_t retkey_value =
        derive_vm_return_key(options.decision_seed, function, program);
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
  entry_builder.CreateStore(
      entry_builder.getInt32(dispatch_index_for_instruction[entry_instruction]),
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
    for (std::size_t bank_position = 0; bank_position < switch_dispatch_banks.size();
         ++bank_position) {
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
        const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(
            program,
            dispatch_index_for_instruction,
            island_for_instruction,
            instruction_indices,
            static_cast<std::uint32_t>(instruction_index),
            decoy_island,
            0x521a000ULL + static_cast<std::uint64_t>(bank_position) * 0x1000ULL +
                instruction_index);
        llvm::ArrayRef<std::uint32_t> real_slot_mapping(slot_mappings[instruction_index]);
        llvm::ArrayRef<std::uint32_t> decoy_slot_mapping(slot_mappings[plan.decoy_instruction]);
        auto* guard_block =
            llvm::BasicBlock::Create(context,
                                     "vm.dispatch.root.guard." + std::to_string(bank_position) +
                                         "." + std::to_string(instruction_index),
                                     &function,
                                     real_block);
        llvm::BasicBlock* decoy_block =
            EmitVmInlineDecoyBlock(function,
                                   rewrite_context,
                                   dispatch_loop_block,
                                   real_slot_mapping,
                                   decoy_slot_mapping,
                                   plan,
                                   "vm.dispatch.root.decoy." + std::to_string(bank_position) + "." +
                                       std::to_string(instruction_index));
        case_it->setSuccessor(guard_block);

        llvm::IRBuilder<> guard_builder(guard_block);
        llvm::Value* opaque_true =
            mba::build_entropy_true_predicate(guard_builder,
                                              function,
                                              std::max<std::uint32_t>(2, options.mba_depth),
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

  emit_vm_terminal_trap(
      function, trap_block, mba_context, 0x521930ULL + program.instructions.size(), trap_shape);
}

}  // namespace obf::vm
