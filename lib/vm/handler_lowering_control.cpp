#include "obf/vm/virtualize_internal.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"

namespace obf::vm {

namespace {

llvm::StringRef branch_shape_marker(branch_handler_shape shape) {
  switch (shape) {
    case branch_handler_shape::direct:
      return "vm.branch.shape.direct";
    case branch_handler_shape::inverted_condition_swap:
      return "vm.branch.shape.invert";
    case branch_handler_shape::neutralized_condition:
      return "vm.branch.shape.neutral";
    case branch_handler_shape::select_condition:
      return "vm.branch.shape.select";
  }
  llvm_unreachable("unknown branch handler shape");
}

llvm::StringRef return_shape_marker(return_handler_shape shape) {
  switch (shape) {
    case return_handler_shape::direct:
      return "vm.return.shape.direct";
    case return_handler_shape::result_slot_roundtrip:
      return "vm.return.shape.slot";
    case return_handler_shape::neutralized_encode:
      return "vm.return.shape.neutral";
    case return_handler_shape::split_encode:
      return "vm.return.shape.split";
  }
  llvm_unreachable("unknown return handler shape");
}

llvm::Value* emit_branch_condition(llvm::IRBuilder<>& builder,
                                   const instruction_rewrite_context& context,
                                   branch_handler_shape shape,
                                   bool& swap_targets) {
  rewrite_function_context& function_context = context.function_context;
  const std::uint64_t instruction_index = context.instruction_index;
  llvm::Value* condition = materialize_value(builder,
                                             function_context.slot_allocas,
                                             context.current_slot_mapping,
                                             function_context.program,
                                             context.instruction.operands[0],
                                             function_context.opaque_seed_slot,
                                             function_context.opaque_seed_base,
                                             function_context.mba_context,
                                             0x16000 + instruction_index);
  swap_targets = false;
  switch (shape) {
    case branch_handler_shape::direct:
      return tag_vm_handler_value(condition, branch_shape_marker(shape));
    case branch_handler_shape::neutralized_condition:
      return builder.CreateXor(condition, builder.getFalse(), branch_shape_marker(shape));
    case branch_handler_shape::select_condition:
      return builder.CreateSelect(
          condition, builder.getTrue(), builder.getFalse(), branch_shape_marker(shape));
    case branch_handler_shape::inverted_condition_swap:
      swap_targets = true;
      return builder.CreateXor(condition, builder.getTrue(), branch_shape_marker(shape));
  }

  llvm_unreachable("unknown branch handler shape");
}

llvm::Value* convert_return_key(llvm::IRBuilder<>& builder,
                                llvm::Value* key,
                                llvm::Type* target_type,
                                llvm::StringRef name) {
  if (key == nullptr || target_type == nullptr || key->getType() == target_type) { return key; }

  return builder.CreateZExtOrTrunc(key, target_type, name);
}

}  // namespace

void apply_edge_assignments(llvm::IRBuilder<>& builder,
                            const instruction_rewrite_context& context,
                            const control_edge& edge,
                            std::uint64_t salt) {
  rewrite_function_context& function_context = context.function_context;
  llvm::SmallVector<llvm::Value*, 8> incoming_values;
  incoming_values.reserve(edge.assignments.size());
  for (const edge_assignment& assignment : edge.assignments) {
    incoming_values.push_back(materialize_value(builder,
                                                function_context.slot_allocas,
                                                context.current_slot_mapping,
                                                function_context.program,
                                                assignment.value,
                                                function_context.opaque_seed_slot,
                                                function_context.opaque_seed_base,
                                                function_context.mba_context,
                                                salt + incoming_values.size() + 1));
  }

  for (std::size_t assignment_index = 0; assignment_index < edge.assignments.size();
       ++assignment_index) {
    store_slot(builder,
               function_context.slot_allocas,
               context.current_slot_mapping,
               function_context.program,
               edge.assignments[assignment_index].slot,
               incoming_values[assignment_index],
               function_context.opaque_seed_slot,
               function_context.opaque_seed_base,
               function_context.mba_context,
               salt + edge.assignments.size() + assignment_index + 1);
  }
}

void rotate_to_mapping(llvm::IRBuilder<>& builder,
                       const instruction_rewrite_context& context,
                       std::uint32_t target_instruction) {
  rewrite_function_context& function_context = context.function_context;
  if (target_instruction >= function_context.slot_mappings.size()) { return; }

  rotate_slot_cells(
      builder,
      function_context.slot_allocas,
      function_context.program,
      context.current_slot_mapping,
      llvm::ArrayRef<std::uint32_t>(function_context.slot_mappings[target_instruction]),
      function_context.mba_context,
      0x8200 + static_cast<std::uint64_t>(context.instruction_index) * 16 + target_instruction);
}

void finish_value_in_builder(llvm::IRBuilder<>& builder,
                             const instruction_rewrite_context& context,
                             llvm::Value* result) {
  rewrite_function_context& function_context = context.function_context;
  const micro_instruction& instruction = context.instruction;
  llvm::Value* next_target = activate_validated_target(builder, context);

  if (instruction.result_slot != invalid_slot) {
    store_slot(builder,
               function_context.slot_allocas,
               context.current_slot_mapping,
               function_context.program,
               instruction.result_slot,
               result,
               function_context.opaque_seed_slot,
               function_context.opaque_seed_base,
               function_context.mba_context,
               0x8300 + static_cast<std::uint64_t>(context.instruction_index) * 16);
  }
  if (context.instruction_index + 1 < function_context.slot_mappings.size()) {
    rotate_to_mapping(builder, context, static_cast<std::uint32_t>(context.instruction_index + 1));
  }
  emit_dispatch(builder,
                function_context,
                next_target,
                0xa000 + static_cast<std::uint64_t>(context.instruction_index) * 32,
                static_cast<std::uint32_t>(context.instruction_index + 1));
}

bool lower_control_instruction(llvm::IRBuilder<>& builder,
                               const instruction_rewrite_context& context) {
  rewrite_function_context& function_context = context.function_context;
  const micro_instruction& instruction = context.instruction;
  const std::uint64_t instruction_index = context.instruction_index;

  switch (instruction.op) {
    case opcode::call: {
      (void)select_call_handler_shape(
          function_context, instruction, instruction_index, 0x14700 + instruction_index);
      const auto emit_call = [&](llvm::IRBuilder<>& call_builder) {
        llvm::SmallVector<llvm::Value*, 8> arguments;
        arguments.reserve(instruction.operands.size() - 1);
        for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
             ++operand_index) {
          arguments.push_back(materialize_value(call_builder,
                                                function_context.slot_allocas,
                                                context.current_slot_mapping,
                                                function_context.program,
                                                instruction.operands[operand_index],
                                                function_context.opaque_seed_slot,
                                                function_context.opaque_seed_base,
                                                function_context.mba_context,
                                                0x14000 + instruction_index * 16 + operand_index));
        }
        llvm::Value* next_target = activate_validated_target(call_builder, context);

        auto* call = call_builder.CreateCall(
            llvm::cast<llvm::FunctionType>(const_cast<llvm::Type*>(instruction.type)),
            materialize_value(call_builder,
                              function_context.slot_allocas,
                              context.current_slot_mapping,
                              function_context.program,
                              instruction.operands[0],
                              function_context.opaque_seed_slot,
                              function_context.opaque_seed_base,
                              function_context.mba_context,
                              0x14100 + instruction_index),
            arguments,
            instruction.result_slot == invalid_slot ? "" : "obf.vm.call");
        call->setCallingConv(static_cast<llvm::CallingConv::ID>(instruction.subtype));
        call->setAttributes(instruction.attributes);
        apply_fast_math_flags(call, instruction.flags);
        if (instruction.result_slot != invalid_slot) {
          store_slot(call_builder,
                     function_context.slot_allocas,
                     context.current_slot_mapping,
                     function_context.program,
                     instruction.result_slot,
                     call,
                     function_context.opaque_seed_slot,
                     function_context.opaque_seed_base,
                     function_context.mba_context,
                     0x14200 + instruction_index);
        }
        if (instruction_index + 1 < function_context.slot_mappings.size()) {
          rotate_to_mapping(
              call_builder, context, static_cast<std::uint32_t>(instruction_index + 1));
        }
        emit_dispatch(call_builder,
                      function_context,
                      next_target,
                      0x14300 + instruction_index,
                      static_cast<std::uint32_t>(instruction_index + 1));
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x14800 + instruction_index) == 0) {
        emit_call(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.call.exec.", emit_call);
      }
      return true;
    }

    case opcode::jump: {
      llvm::Value* next_target = activate_validated_target(builder, context, 0);
      apply_edge_assignments(builder, context, instruction.edges[0], 0x15000 + instruction_index);
      rotate_to_mapping(
          builder,
          context,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);
      emit_dispatch(
          builder,
          function_context,
          next_target,
          0x15200 + instruction_index,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);
      return true;
    }

    case opcode::branch: {
      const branch_handler_shape shape = select_branch_handler_shape(
          function_context, instruction, instruction_index, 0x16700 + instruction_index);
      auto* true_block =
          llvm::BasicBlock::Create(function_context.function.getContext(),
                                   "vm.edge.true." + std::to_string(instruction_index),
                                   &function_context.function);
      auto* false_block =
          llvm::BasicBlock::Create(function_context.function.getContext(),
                                   "vm.edge.false." + std::to_string(instruction_index),
                                   &function_context.function);
      bool swap_targets = false;
      llvm::Value* condition = emit_branch_condition(builder, context, shape, swap_targets);
      builder.CreateCondBr(condition,
                           swap_targets ? false_block : true_block,
                           swap_targets ? true_block : false_block);

      llvm::IRBuilder<> true_builder(true_block);
      llvm::Value* true_target = activate_validated_target(true_builder, context, 0);
      apply_edge_assignments(
          true_builder, context, instruction.edges[0], 0x16100 + instruction_index);
      rotate_to_mapping(
          true_builder,
          context,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);
      emit_dispatch(
          true_builder,
          function_context,
          true_target,
          0x16300 + instruction_index,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);

      llvm::IRBuilder<> false_builder(false_block);
      llvm::Value* false_target = activate_validated_target(false_builder, context, 1);
      apply_edge_assignments(
          false_builder, context, instruction.edges[1], 0x16400 + instruction_index);
      rotate_to_mapping(
          false_builder,
          context,
          function_context.program.blocks[instruction.edges[1].target_block].first_instruction);
      emit_dispatch(
          false_builder,
          function_context,
          false_target,
          0x16600 + instruction_index,
          function_context.program.blocks[instruction.edges[1].target_block].first_instruction);
      return true;
    }

    case opcode::switch_op: {
      auto* default_block =
          llvm::BasicBlock::Create(function_context.function.getContext(),
                                   "vm.switch.default." + std::to_string(instruction_index),
                                   &function_context.function);
      auto* switch_inst = builder.CreateSwitch(materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[0],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x17000 + instruction_index),
                                               default_block,
                                               instruction.case_values.size());

      llvm::SmallVector<llvm::BasicBlock*, 8> case_blocks;
      case_blocks.reserve(instruction.case_values.size());
      for (std::size_t case_index = 0; case_index < instruction.case_values.size(); ++case_index) {
        auto* case_block =
            llvm::BasicBlock::Create(function_context.function.getContext(),
                                     "vm.switch.case." + std::to_string(instruction_index) + "." +
                                         std::to_string(case_index),
                                     &function_context.function);
        switch_inst->addCase(const_cast<llvm::ConstantInt*>(instruction.case_values[case_index]),
                             case_block);
        case_blocks.push_back(case_block);
      }

      llvm::IRBuilder<> default_builder(default_block);
      llvm::Value* default_target = activate_validated_target(default_builder, context, 0);
      apply_edge_assignments(
          default_builder, context, instruction.edges[0], 0x17100 + instruction_index);
      rotate_to_mapping(
          default_builder,
          context,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);
      emit_dispatch(
          default_builder,
          function_context,
          default_target,
          0x17300 + instruction_index,
          function_context.program.blocks[instruction.edges[0].target_block].first_instruction);

      for (std::size_t case_index = 0; case_index < case_blocks.size(); ++case_index) {
        llvm::IRBuilder<> case_builder(case_blocks[case_index]);
        llvm::Value* case_target = activate_validated_target(
            case_builder, context, static_cast<std::uint32_t>(case_index + 1));
        apply_edge_assignments(case_builder,
                               context,
                               instruction.edges[case_index + 1],
                               0x17400 + instruction_index * 8 + case_index);
        rotate_to_mapping(
            case_builder,
            context,
            function_context.program.blocks[instruction.edges[case_index + 1].target_block]
                .first_instruction);
        emit_dispatch(
            case_builder,
            function_context,
            case_target,
            0x17600 + instruction_index * 8 + case_index,
            function_context.program.blocks[instruction.edges[case_index + 1].target_block]
                .first_instruction);
      }
      return true;
    }

    case opcode::unreachable_op:
      builder.CreateBr(function_context.trap_block);
      return true;

    case opcode::ret:
      if (instruction.operands.empty()) {
        if (function_context.state_island_body) {
          builder.CreateRet(
              apply_vm_island_status_choreography(builder,
                                                  function_context.function,
                                                  function_context.bytecode_seed,
                                                  builder.getInt32(vm_island_done_status),
                                                  static_cast<std::uint32_t>(instruction_index),
                                                  0x17f80 + instruction_index));
        } else {
          builder.CreateRetVoid();
        }
      } else {
        const return_handler_shape shape = select_return_handler_shape(
            function_context, instruction, instruction_index, 0x17f00 + instruction_index);
        llvm::Value* ret_val = materialize_value(builder,
                                                 function_context.slot_allocas,
                                                 context.current_slot_mapping,
                                                 function_context.program,
                                                 instruction.operands[0],
                                                 function_context.opaque_seed_slot,
                                                 function_context.opaque_seed_base,
                                                 function_context.mba_context,
                                                 0x18000 + instruction_index);
        if (function_context.retkey_global != nullptr && ret_val->getType()->isIntegerTy()) {
          const std::uint64_t ret_salt = 0x1a000 + instruction_index * 16;
          auto* retkey_load = builder.CreateLoad(
              builder.getInt64Ty(), function_context.retkey_global, "obf.vm.ret.retkey");
          llvm::Value* token_component = nullptr;
          if (function_context.hidden_token_arg != nullptr) {
            token_component = function_context.hidden_token_arg;
          } else if (function_context.hidden_token_slot != nullptr) {
            token_component = builder.CreateLoad(
                builder.getInt64Ty(), function_context.hidden_token_slot, "obf.vm.ret.token.state");
          } else {
            token_component = builder.getInt64(function_context.opaque_seed_base);
          }
          if (token_component->getType() != builder.getInt64Ty()) {
            token_component = builder.CreateZExtOrTrunc(
                token_component, builder.getInt64Ty(), "obf.vm.ret.token.cast");
          }
          if (shape == return_handler_shape::result_slot_roundtrip) {
            ret_val = roundtrip_vm_handler_value(builder, ret_val, return_shape_marker(shape));
          }

          if (shape == return_handler_shape::split_encode) {
            llvm::Value* retkey_trunc =
                convert_return_key(builder, retkey_load, ret_val->getType(), "obf.vm.ret.key.cast");
            llvm::Value* token_trunc = convert_return_key(
                builder, token_component, ret_val->getType(), "obf.vm.ret.token.cast");
            llvm::Value* partial = mba::create_xor(builder,
                                                   ret_val,
                                                   retkey_trunc,
                                                   function_context.mba_context,
                                                   ret_salt + 3,
                                                   return_shape_marker(shape));
            ret_val = mba::create_xor(builder,
                                      partial,
                                      token_trunc,
                                      function_context.mba_context,
                                      ret_salt + 4,
                                      "obf.vm.ret.encoded");
          } else {
            llvm::Value* token_key = mba::create_xor(builder,
                                                     retkey_load,
                                                     token_component,
                                                     function_context.mba_context,
                                                     ret_salt + 2,
                                                     "obf.vm.ret.tokenkey");
            llvm::Value* key_trunc =
                convert_return_key(builder, token_key, ret_val->getType(), "obf.vm.ret.key.cast");
            if (shape == return_handler_shape::direct) {
              function_context.function.addFnAttr(return_shape_marker(shape));
            } else if (shape == return_handler_shape::neutralized_encode) {
              key_trunc = builder.CreateXor(
                  key_trunc,
                  llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(ret_val->getType()), 0),
                  return_shape_marker(shape));
            }
            ret_val = mba::create_xor(builder,
                                      ret_val,
                                      key_trunc,
                                      function_context.mba_context,
                                      ret_salt + 4,
                                      "obf.vm.ret.encoded");
          }
        }
        if (function_context.state_island_body) {
          if (function_context.return_value_slot != nullptr) {
            builder.CreateStore(ret_val, function_context.return_value_slot);
          }
          builder.CreateRet(
              apply_vm_island_status_choreography(builder,
                                                  function_context.function,
                                                  function_context.bytecode_seed,
                                                  builder.getInt32(vm_island_done_status),
                                                  static_cast<std::uint32_t>(instruction_index),
                                                  0x1af00 + instruction_index));
        } else {
          builder.CreateRet(ret_val);
        }
      }
      return true;

    default:
      return false;
  }
}

}  // namespace obf::vm
