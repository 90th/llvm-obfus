#include "obf/vm/internal/virtualize_dispatch_return.h"
#include "obf/vm/internal/virtualize_island_topology.h"
#include "obf/vm/internal/virtualize_anchor_scattering.h"
#include "obf/vm/virtualize_internal.h"

#include "obf/support/generated_names.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <string>
#include <vector>

namespace obf::vm {

template <typename Shape>
Shape select_vm_body_shape_variant(const llvm::Function& function,
                                   std::uint64_t bytecode_seed,
                                   std::uint64_t detail,
                                   std::uint64_t salt,
                                   std::uint32_t variant_count) {
  std::uint64_t variant =
      (mix_seed(bytecode_seed, salt ^ detail) % static_cast<std::uint64_t>(variant_count));
  return static_cast<Shape>(variant);
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
      const std::uint64_t lhs_family = mix_seed(
          bytecode_seed, salt ^ (0x51573000ULL + opcode_family(program.instructions[lhs].op)));
      const std::uint64_t rhs_family = mix_seed(
          bytecode_seed, salt ^ (0x51573000ULL + opcode_family(program.instructions[rhs].op)));
      if (lhs_family != rhs_family) { return lhs_family < rhs_family; }
    }

    const std::uint64_t lhs_key = mix_seed(bytecode_seed, salt ^ (0x51573100ULL + lhs));
    const std::uint64_t rhs_key = mix_seed(bytecode_seed, salt ^ (0x51573100ULL + rhs));
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });
  return order;
}

llvm::SmallVector<std::uint32_t, 8> build_vm_index_emission_order(std::uint32_t count,
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
      llvm::Value* trap_gate = trap_builder.CreateICmpEQ(gate_lhs, gate_rhs, "vm.trap.gate");
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

llvm::BasicBlock* create_handler_success_route(rewrite_function_context& rewrite_context,
                                               llvm::BasicBlock* handler_block,
                                               std::size_t instruction_index) {
  llvm::Function& function = rewrite_context.function;
  function.addFnAttr("vm.handler.route.trampoline");
  auto* route_block =
      llvm::BasicBlock::Create(function.getContext(),
                               "obf.vm.route.entry." + std::to_string(instruction_index),
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
  const std::uint64_t body_detail = (static_cast<std::uint64_t>(island_index) << 32) |
                                    static_cast<std::uint64_t>(subhelper_index);
  const vm_body_layout_shape body_layout_shape = select_vm_body_layout_shape(
      dispatcher, bytecode_seed, body_detail, owned_instructions.size());
  const vm_status_trap_shape trap_shape =
      select_vm_status_trap_shape(dispatcher, bytecode_seed, body_detail);
  note_vm_function_marker(dispatcher, vm_body_layout_shape_marker(body_layout_shape));
  const llvm::SmallVector<std::size_t, 32> emission_order = build_vm_instruction_emission_order(
      program, owned_instructions, bytecode_seed, body_layout_shape, 0x521050ULL ^ body_detail);
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
  llvm::AllocaInst* opcode_predicate_slot =
      entry_builder.CreateAlloca(entry_builder.getInt32Ty(), nullptr, "obf.vm.pred.slot");

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

  const mba::builder_context mba_context{
      .entropy_anchor = mba::get_or_create_entropy_anchor(*module),
      .seed_base = opaque_seed_base,
      .depth = options.mba_depth,
      .max_ir_instructions_override = options.mba_max_ir_instructions,
      .enable_polynomial_override = options.mba_enable_polynomial,
      .enable_multiplication_override = options.mba_enable_multiplication};
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
        route_prefix + "guard." + std::to_string(island_index) + "." +
            std::to_string(subhelper_index) + "." + std::to_string(instruction_index),
        &dispatcher,
        real_block);
    const std::uint32_t decoy_island =
        island_for_instruction.empty() ? island_index : (island_index + 1) % island_count;
    const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(
        program,
        dispatch_index_for_instruction,
        island_for_instruction,
        owned_instructions,
        static_cast<std::uint32_t>(instruction_index),
        decoy_island,
        0x521020ULL + static_cast<std::uint64_t>(island_index) * 0x1000ULL +
            static_cast<std::uint64_t>(subhelper_index) * 0x100ULL + instruction_index);
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
    entry_switch->addCase(
        dispatch_builder.getInt32(dispatch_index_for_instruction[instruction_index]), guard_block);

    llvm::IRBuilder<> guard_builder(guard_block);
    llvm::Value* opaque_true =
        mba::build_entropy_true_predicate(guard_builder,
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
    const std::uint64_t retkey_value =
        derive_vm_return_key(options.decision_seed, function, program);
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

  const mba::builder_context mba_context{
      .entropy_anchor = mba::get_or_create_entropy_anchor(*module),
      .seed_base = opaque_seed_base,
      .depth = options.mba_depth,
      .max_ir_instructions_override = options.mba_max_ir_instructions,
      .enable_polynomial_override = options.mba_enable_polynomial,
      .enable_multiplication_override = options.mba_enable_multiplication};
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
  const llvm::SmallVector<std::uint32_t, 8> helper_emission_order = build_vm_index_emission_order(
      island_count, bytecode_seed, root_layout_shape, 0x521620ULL + island_count);
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

    llvm::Function* decoy_helper =
        llvm::Function::Create(helper_type,
                               llvm::GlobalValue::InternalLinkage,
                               MakeVmIslandDecoyHelperName(*module, bytecode_seed, island_index),
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
    const std::uint32_t entry_instruction =
        owned_instructions.empty() ? 0 : static_cast<std::uint32_t>(owned_instructions.front());
    const std::uint32_t decoy_island = (island_index + 1) % helpers.size();
    const VmDecoyRoutePlan plan = BuildVmDecoyRoutePlan(program,
                                                        dispatch_index_for_instruction,
                                                        island_for_instruction,
                                                        owned_instructions,
                                                        entry_instruction,
                                                        decoy_island,
                                                        0x521680ULL + island_index);

    llvm::IRBuilder<> guard_builder(guard_block);
    llvm::Value* opaque_true =
        mba::build_entropy_true_predicate(guard_builder,
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
    auto* decoy_status =
        decoy_call_builder.CreateCall(decoy_helpers[island_index]->getFunctionType(),
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
    const std::uint32_t entry_instruction =
        owned_instructions.empty() ? 0 : static_cast<std::uint32_t>(owned_instructions.front());
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

}  // namespace obf::vm
