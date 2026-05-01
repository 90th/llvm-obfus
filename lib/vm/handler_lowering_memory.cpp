#include "obf/vm/virtualize_internal.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

namespace obf::vm {

namespace {

struct non_pointer_memory_access {
  llvm::AllocaInst* scratch = nullptr;
  llvm::Align scratch_alignment = llvm::Align(1);
  std::uint64_t size = 0;
  llvm::MaybeAlign pointer_alignment;

  [[nodiscard]] bool valid() const { return scratch != nullptr && size != 0; }
};

non_pointer_memory_access prepare_non_pointer_memory_access(llvm::IRBuilder<>& builder,
                                                            llvm::Type* value_type,
                                                            std::uint32_t pointer_alignment,
                                                            llvm::StringRef scratch_name) {
  non_pointer_memory_access access;
  if (value_type == nullptr || value_type->isPointerTy()) { return access; }

  const llvm::DataLayout* data_layout = get_builder_data_layout(builder);
  llvm::BasicBlock* block = builder.GetInsertBlock();
  llvm::Function* function = block != nullptr ? block->getParent() : nullptr;
  if (data_layout == nullptr || function == nullptr || !value_type->isSized()) { return access; }

  llvm::TypeSize storage_size = data_layout->getTypeStoreSize(value_type);
  if (storage_size.isScalable() || storage_size.getFixedValue() == 0) { return access; }

  llvm::BasicBlock& entry_block = function->getEntryBlock();
  llvm::IRBuilder<> entry_builder(&entry_block, entry_block.begin());
  access.scratch = entry_builder.CreateAlloca(value_type, nullptr, scratch_name);
  access.scratch_alignment = data_layout->getPrefTypeAlign(value_type);
  access.scratch->setAlignment(access.scratch_alignment);
  access.size = storage_size.getFixedValue();
  if (pointer_alignment != 0) { access.pointer_alignment = llvm::Align(pointer_alignment); }
  return access;
}

llvm::Value* load_non_pointer_value_from_memory(llvm::IRBuilder<>& builder,
                                                llvm::Value* address,
                                                llvm::Type* value_type,
                                                std::uint32_t pointer_alignment,
                                                llvm::StringRef name_prefix = "obf.vm.load.mem") {
  if (address == nullptr || !address->getType()->isPointerTy()) { return nullptr; }

  const std::string base_name = name_prefix.empty() ? "obf.vm.load.mem" : name_prefix.str();
  non_pointer_memory_access access = prepare_non_pointer_memory_access(
      builder, value_type, pointer_alignment, base_name + ".scratch");
  if (!access.valid()) { return nullptr; }

  (void)builder.CreateMemCpy(access.scratch,
                             llvm::MaybeAlign(access.scratch_alignment),
                             address,
                             access.pointer_alignment,
                             access.size);
  auto* load = builder.CreateLoad(value_type, access.scratch, base_name);
  load->setAlignment(access.scratch_alignment);
  return load;
}

bool store_non_pointer_value_to_memory(llvm::IRBuilder<>& builder,
                                       llvm::Value* address,
                                       llvm::Value* value,
                                       llvm::Type* value_type,
                                       std::uint32_t pointer_alignment,
                                       llvm::StringRef name_prefix = "obf.vm.store.mem") {
  if (address == nullptr || value == nullptr || !address->getType()->isPointerTy() ||
      value_type == nullptr || value->getType() != value_type) {
    return false;
  }

  const std::string base_name = name_prefix.empty() ? "obf.vm.store.mem" : name_prefix.str();
  non_pointer_memory_access access = prepare_non_pointer_memory_access(
      builder, value_type, pointer_alignment, base_name + ".scratch");
  if (!access.valid()) { return false; }

  auto* scratch_store = builder.CreateStore(value, access.scratch);
  scratch_store->setAlignment(access.scratch_alignment);
  (void)builder.CreateMemCpy(address,
                             access.pointer_alignment,
                             access.scratch,
                             llvm::MaybeAlign(access.scratch_alignment),
                             access.size);
  return true;
}

llvm::StringRef memory_shape_marker(memory_handler_shape shape) {
  switch (shape) {
    case memory_handler_shape::direct:
      return "vm.memory.shape.direct";
    case memory_handler_shape::pointer_roundtrip:
      return "vm.memory.shape.ptr";
    case memory_handler_shape::offset_neutralized:
      return "vm.memory.shape.offset";
    case memory_handler_shape::addr_select_neutralized:
      return "vm.memory.shape.select";
    case memory_handler_shape::value_slot_roundtrip:
      return "vm.memory.shape.slot";
  }
  llvm_unreachable("unknown memory handler shape");
}

llvm::StringRef gep_shape_marker(gep_handler_shape shape) {
  switch (shape) {
    case gep_handler_shape::direct:
      return "vm.gep.shape.direct";
    case gep_handler_shape::split_index_add:
      return "vm.gep.shape.split";
    case gep_handler_shape::ptrint_roundtrip:
      return "vm.gep.shape.ptrint";
    case gep_handler_shape::offset_bias:
      return "vm.gep.shape.bias";
    case gep_handler_shape::select_equivalent_base:
      return "vm.gep.shape.select";
  }
  llvm_unreachable("unknown gep handler shape");
}

llvm::Value* apply_memory_address_shape(llvm::IRBuilder<>& builder,
                                        llvm::Value* address,
                                        memory_handler_shape& shape) {
  if (address == nullptr || !address->getType()->isPointerTy()) { return address; }

  switch (shape) {
    case memory_handler_shape::direct:
      return tag_vm_handler_value(address, memory_shape_marker(shape));
    case memory_handler_shape::pointer_roundtrip:
      return roundtrip_vm_handler_value(builder, address, memory_shape_marker(shape));
    case memory_handler_shape::addr_select_neutralized: {
      llvm::Value* roundtrip =
          roundtrip_vm_handler_value(builder, address, "vm.memory.shape.select.base");
      return builder.CreateSelect(
          builder.getTrue(), address, roundtrip, memory_shape_marker(shape));
    }
    case memory_handler_shape::offset_neutralized: {
      auto* carrier_type = get_pointer_carrier_type(builder, address->getType());
      if (carrier_type == nullptr) {
        shape = memory_handler_shape::pointer_roundtrip;
        return roundtrip_vm_handler_value(builder, address, memory_shape_marker(shape));
      }

      llvm::Value* carrier = builder.CreatePtrToInt(address, carrier_type, "obf.vm.mem.addr.raw");
      llvm::Value* biased = builder.CreateAdd(
          carrier, llvm::ConstantInt::get(carrier_type, 1), "obf.vm.mem.addr.bias");
      llvm::Value* unbiased = builder.CreateSub(
          biased, llvm::ConstantInt::get(carrier_type, 1), memory_shape_marker(shape));
      return builder.CreateIntToPtr(
          unbiased, llvm::cast<llvm::PointerType>(address->getType()), "obf.vm.mem.addr.ptr");
    }
    case memory_handler_shape::value_slot_roundtrip:
      return address;
  }

  llvm_unreachable("unknown memory handler shape");
}

llvm::Value* apply_memory_value_shape(llvm::IRBuilder<>& builder,
                                      llvm::Value* value,
                                      llvm::Value* address,
                                      memory_handler_shape shape) {
  switch (shape) {
    case memory_handler_shape::direct:
      if (llvm::Value* tagged = tag_vm_handler_value(value, memory_shape_marker(shape))) {
        return tagged;
      }
      (void)tag_vm_handler_value(address, memory_shape_marker(shape));
      return value;
    case memory_handler_shape::value_slot_roundtrip:
      return roundtrip_vm_handler_value(builder, value, memory_shape_marker(shape));
    case memory_handler_shape::pointer_roundtrip:
    case memory_handler_shape::offset_neutralized:
    case memory_handler_shape::addr_select_neutralized:
      return value;
  }

  llvm_unreachable("unknown memory handler shape");
}

bool apply_gep_index_shape(llvm::IRBuilder<>& builder,
                           llvm::SmallVectorImpl<llvm::Value*>& indices,
                           gep_handler_shape shape) {
  if (shape != gep_handler_shape::split_index_add && shape != gep_handler_shape::offset_bias) {
    return false;
  }

  for (llvm::Value*& index : indices) {
    auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(index->getType());
    if (integer_type == nullptr || llvm::isa<llvm::Constant>(index)) { continue; }

    if (shape == gep_handler_shape::split_index_add) {
      index = builder.CreateAdd(
          index, llvm::ConstantInt::get(integer_type, 0), gep_shape_marker(shape));
      return true;
    }

    llvm::Value* biased =
        builder.CreateAdd(index, llvm::ConstantInt::get(integer_type, 1), "obf.vm.gep.bias");
    index =
        builder.CreateSub(biased, llvm::ConstantInt::get(integer_type, 1), gep_shape_marker(shape));
    return true;
  }

  return false;
}

llvm::Value* apply_gep_base_shape(llvm::IRBuilder<>& builder,
                                  llvm::Value* pointer,
                                  const micro_instruction& instruction,
                                  gep_handler_shape& shape) {
  if (pointer == nullptr || !pointer->getType()->isPointerTy()) { return pointer; }

  switch (shape) {
    case gep_handler_shape::direct:
      return tag_vm_handler_value(pointer, gep_shape_marker(shape));
    case gep_handler_shape::select_equivalent_base: {
      llvm::Value* roundtrip =
          roundtrip_vm_handler_value(builder, pointer, "vm.gep.shape.select.base");
      return builder.CreateSelect(builder.getTrue(), pointer, roundtrip, gep_shape_marker(shape));
    }
    case gep_handler_shape::ptrint_roundtrip: {
      if (instruction.op == opcode::gep_inbounds) {
        shape = gep_handler_shape::select_equivalent_base;
        return apply_gep_base_shape(builder, pointer, instruction, shape);
      }

      auto* carrier_type = get_pointer_carrier_type(builder, pointer->getType());
      if (carrier_type == nullptr) {
        shape = gep_handler_shape::select_equivalent_base;
        return apply_gep_base_shape(builder, pointer, instruction, shape);
      }

      llvm::Value* carrier = builder.CreatePtrToInt(pointer, carrier_type, "obf.vm.gep.ptrint");
      return builder.CreateIntToPtr(
          carrier, llvm::cast<llvm::PointerType>(pointer->getType()), gep_shape_marker(shape));
    }
    case gep_handler_shape::split_index_add:
    case gep_handler_shape::offset_bias:
      return pointer;
  }

  llvm_unreachable("unknown gep handler shape");
}

}  // namespace

bool lower_memory_instruction(llvm::IRBuilder<>& builder,
                              const instruction_rewrite_context& context) {
  rewrite_function_context& function_context = context.function_context;
  const micro_instruction& instruction = context.instruction;
  const std::uint64_t instruction_index = context.instruction_index;

  switch (instruction.op) {
    case opcode::load_int:
    case opcode::load_float:
    case opcode::load_vector: {
      const memory_handler_shape selected_shape = select_memory_handler_shape(
          function_context, instruction, instruction_index, 0x11700 + instruction_index);
      const auto emit_load = [&](llvm::IRBuilder<>& load_builder) {
        memory_handler_shape shape = selected_shape;
        llvm::Value* pointer_address = materialize_value(load_builder,
                                                         function_context.slot_allocas,
                                                         context.current_slot_mapping,
                                                         function_context.program,
                                                         instruction.operands[0],
                                                         function_context.opaque_seed_slot,
                                                         function_context.opaque_seed_base,
                                                         function_context.mba_context,
                                                         0x11000 + instruction_index);
        pointer_address = apply_memory_address_shape(load_builder, pointer_address, shape);
        llvm::Value* load =
            load_non_pointer_value_from_memory(load_builder,
                                               pointer_address,
                                               const_cast<llvm::Type*>(instruction.type),
                                               instruction.immediate,
                                               "obf.vm.load.mem");
        if (load == nullptr) {
          auto* direct_load = load_builder.CreateLoad(
              const_cast<llvm::Type*>(instruction.type), pointer_address, "obf.vm.load");
          if (instruction.immediate != 0) {
            direct_load->setAlignment(llvm::Align(instruction.immediate));
          }
          load = direct_load;
        }
        load = apply_memory_value_shape(load_builder, load, pointer_address, shape);
        finish_value_in_builder(load_builder, context, load);
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x11800 + instruction_index) == 0) {
        emit_load(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.load.exec.", emit_load);
      }
      return true;
    }

    case opcode::load_ptr: {
      const memory_handler_shape selected_shape = select_memory_handler_shape(
          function_context, instruction, instruction_index, 0x11780 + instruction_index);
      const auto emit_pointer_load = [&](llvm::IRBuilder<>& load_builder) {
        memory_handler_shape shape = selected_shape;
        llvm::Value* pointer_address = materialize_value(load_builder,
                                                         function_context.slot_allocas,
                                                         context.current_slot_mapping,
                                                         function_context.program,
                                                         instruction.operands[0],
                                                         function_context.opaque_seed_slot,
                                                         function_context.opaque_seed_base,
                                                         function_context.mba_context,
                                                         0x11000 + instruction_index);
        pointer_address = apply_memory_address_shape(load_builder, pointer_address, shape);
        llvm::Value* load = load_pointer_value_from_memory(
            load_builder,
            pointer_address,
            const_cast<llvm::Type*>(instruction.type),
            function_context.mba_context,
            0x11080 + instruction_index,
            instruction.immediate != 0 ? llvm::MaybeAlign(llvm::Align(instruction.immediate))
                                       : llvm::MaybeAlign(),
            "obf.vm.load.ptr");
        if (load == nullptr) {
          auto* direct_load = load_builder.CreateLoad(
              const_cast<llvm::Type*>(instruction.type), pointer_address, "obf.vm.load");
          if (instruction.immediate != 0) {
            direct_load->setAlignment(llvm::Align(instruction.immediate));
          }
          load = direct_load;
        }
        load = apply_memory_value_shape(load_builder, load, pointer_address, shape);
        finish_value_in_builder(load_builder, context, load);
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x11800 + instruction_index) == 0) {
        emit_pointer_load(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.load.exec.", emit_pointer_load);
      }
      return true;
    }

    case opcode::store_int:
    case opcode::store_float:
    case opcode::store_vector: {
      const memory_handler_shape selected_shape = select_memory_handler_shape(
          function_context, instruction, instruction_index, 0x12700 + instruction_index);
      const auto emit_store = [&](llvm::IRBuilder<>& store_builder) {
        memory_handler_shape shape = selected_shape;
        llvm::Value* value = materialize_value(store_builder,
                                               function_context.slot_allocas,
                                               context.current_slot_mapping,
                                               function_context.program,
                                               instruction.operands[0],
                                               function_context.opaque_seed_slot,
                                               function_context.opaque_seed_base,
                                               function_context.mba_context,
                                               0x12000 + instruction_index);
        llvm::Value* pointer_address = materialize_value(store_builder,
                                                         function_context.slot_allocas,
                                                         context.current_slot_mapping,
                                                         function_context.program,
                                                         instruction.operands[1],
                                                         function_context.opaque_seed_slot,
                                                         function_context.opaque_seed_base,
                                                         function_context.mba_context,
                                                         0x12100 + instruction_index);
        pointer_address = apply_memory_address_shape(store_builder, pointer_address, shape);
        value = apply_memory_value_shape(store_builder, value, pointer_address, shape);
        if (!store_non_pointer_value_to_memory(store_builder,
                                               pointer_address,
                                               value,
                                               const_cast<llvm::Type*>(instruction.type),
                                               instruction.immediate,
                                               "obf.vm.store.mem")) {
          auto* store = store_builder.CreateStore(value, pointer_address);
          if (instruction.immediate != 0) {
            store->setAlignment(llvm::Align(instruction.immediate));
          }
        }
        if (instruction_index + 1 < function_context.slot_mappings.size()) {
          rotate_to_mapping(
              store_builder, context, static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value* next_target = decode_target_dispatch(store_builder,
                                                          function_context,
                                                          context.layout.fallthrough_target_offset,
                                                          0x12200 + instruction_index);
        emit_dispatch(store_builder,
                      function_context,
                      next_target,
                      0x12300 + instruction_index,
                      static_cast<std::uint32_t>(instruction_index + 1));
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x12800 + instruction_index) == 0) {
        emit_store(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.store.exec.", emit_store);
      }
      return true;
    }

    case opcode::store_ptr: {
      const memory_handler_shape selected_shape = select_memory_handler_shape(
          function_context, instruction, instruction_index, 0x12780 + instruction_index);
      const auto emit_pointer_store = [&](llvm::IRBuilder<>& store_builder) {
        memory_handler_shape shape = selected_shape;
        llvm::Value* pointer_address = materialize_value(store_builder,
                                                         function_context.slot_allocas,
                                                         context.current_slot_mapping,
                                                         function_context.program,
                                                         instruction.operands[1],
                                                         function_context.opaque_seed_slot,
                                                         function_context.opaque_seed_base,
                                                         function_context.mba_context,
                                                         0x12100 + instruction_index);
        pointer_address = apply_memory_address_shape(store_builder, pointer_address, shape);
        llvm::StoreInst* store = nullptr;
        llvm::Value* stored_pointer_value = materialize_value(store_builder,
                                                              function_context.slot_allocas,
                                                              context.current_slot_mapping,
                                                              function_context.program,
                                                              instruction.operands[0],
                                                              function_context.opaque_seed_slot,
                                                              function_context.opaque_seed_base,
                                                              function_context.mba_context,
                                                              0x12040 + instruction_index);
        stored_pointer_value =
            apply_memory_value_shape(store_builder, stored_pointer_value, pointer_address, shape);
        if (llvm::Value* carrier = materialize_pointer_carrier(store_builder,
                                                               stored_pointer_value,
                                                               function_context.opaque_seed_slot,
                                                               function_context.opaque_seed_base,
                                                               function_context.mba_context,
                                                               0x12000 + instruction_index)) {
          store = store_pointer_carrier_to_memory(
              store_builder,
              pointer_address,
              carrier,
              const_cast<llvm::Type*>(instruction.type),
              function_context.mba_context,
              0x12080 + instruction_index,
              instruction.immediate != 0 ? llvm::MaybeAlign(llvm::Align(instruction.immediate))
                                         : llvm::MaybeAlign());
        }
        if (store == nullptr) {
          if (llvm::Value* carrier =
                  materialize_pointer_carrier_from_value_ref(store_builder,
                                                             function_context.slot_allocas,
                                                             context.current_slot_mapping,
                                                             function_context.program,
                                                             instruction.operands[0],
                                                             function_context.opaque_seed_slot,
                                                             function_context.opaque_seed_base,
                                                             function_context.mba_context,
                                                             0x12000 + instruction_index)) {
            store = store_pointer_carrier_to_memory(
                store_builder,
                pointer_address,
                carrier,
                const_cast<llvm::Type*>(instruction.type),
                function_context.mba_context,
                0x12080 + instruction_index,
                instruction.immediate != 0 ? llvm::MaybeAlign(llvm::Align(instruction.immediate))
                                           : llvm::MaybeAlign());
          }
        }
        if (store == nullptr) {
          store = store_pointer_value_to_memory(
              store_builder,
              pointer_address,
              stored_pointer_value,
              const_cast<llvm::Type*>(instruction.type),
              function_context.opaque_seed_slot,
              function_context.opaque_seed_base,
              function_context.mba_context,
              0x120c0 + instruction_index,
              instruction.immediate != 0 ? llvm::MaybeAlign(llvm::Align(instruction.immediate))
                                         : llvm::MaybeAlign());
        }
        if (store == nullptr) {
          store = store_builder.CreateStore(stored_pointer_value, pointer_address);
          if (instruction.immediate != 0) {
            store->setAlignment(llvm::Align(instruction.immediate));
          }
        }
        if (instruction_index + 1 < function_context.slot_mappings.size()) {
          rotate_to_mapping(
              store_builder, context, static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value* next_target = decode_target_dispatch(store_builder,
                                                          function_context,
                                                          context.layout.fallthrough_target_offset,
                                                          0x12200 + instruction_index);
        emit_dispatch(store_builder,
                      function_context,
                      next_target,
                      0x12300 + instruction_index,
                      static_cast<std::uint32_t>(instruction_index + 1));
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x12800 + instruction_index) == 0) {
        emit_pointer_store(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.store.exec.", emit_pointer_store);
      }
      return true;
    }

    case opcode::extract_element:
      finish_value(builder,
                   context,
                   builder.CreateExtractElement(materialize_value(builder,
                                                                  function_context.slot_allocas,
                                                                  context.current_slot_mapping,
                                                                  function_context.program,
                                                                  instruction.operands[0],
                                                                  function_context.opaque_seed_slot,
                                                                  function_context.opaque_seed_base,
                                                                  function_context.mba_context,
                                                                  0x12900 + instruction_index),
                                                materialize_value(builder,
                                                                  function_context.slot_allocas,
                                                                  context.current_slot_mapping,
                                                                  function_context.program,
                                                                  instruction.operands[1],
                                                                  function_context.opaque_seed_slot,
                                                                  function_context.opaque_seed_base,
                                                                  function_context.mba_context,
                                                                  0x12910 + instruction_index),
                                                "obf.vm.extract.element"));
      return true;

    case opcode::insert_element:
      finish_value(builder,
                   context,
                   builder.CreateInsertElement(materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[0],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x12920 + instruction_index),
                                               materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[1],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x12930 + instruction_index),
                                               materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[2],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x12940 + instruction_index),
                                               "obf.vm.insert.element"));
      return true;

    case opcode::shuffle_vector: {
      llvm::SmallVector<int, 8> mask;
      mask.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt* mask_value : instruction.case_values) {
        mask.push_back(mask_value == nullptr ? -1 : static_cast<int>(mask_value->getSExtValue()));
      }
      finish_value(builder,
                   context,
                   builder.CreateShuffleVector(materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[0],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x12950 + instruction_index),
                                               materialize_value(builder,
                                                                 function_context.slot_allocas,
                                                                 context.current_slot_mapping,
                                                                 function_context.program,
                                                                 instruction.operands[1],
                                                                 function_context.opaque_seed_slot,
                                                                 function_context.opaque_seed_base,
                                                                 function_context.mba_context,
                                                                 0x12960 + instruction_index),
                                               mask,
                                               "obf.vm.shuffle.vector"));
      return true;
    }

    case opcode::extract_value: {
      llvm::SmallVector<unsigned, 8> indices;
      indices.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt* index_value : instruction.case_values) {
        indices.push_back(
            index_value == nullptr ? 0U : static_cast<unsigned>(index_value->getZExtValue()));
      }
      finish_value(builder,
                   context,
                   builder.CreateExtractValue(materialize_value(builder,
                                                                function_context.slot_allocas,
                                                                context.current_slot_mapping,
                                                                function_context.program,
                                                                instruction.operands[0],
                                                                function_context.opaque_seed_slot,
                                                                function_context.opaque_seed_base,
                                                                function_context.mba_context,
                                                                0x12970 + instruction_index),
                                              indices,
                                              "obf.vm.extract.value"));
      return true;
    }

    case opcode::insert_value: {
      llvm::SmallVector<unsigned, 8> indices;
      indices.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt* index_value : instruction.case_values) {
        indices.push_back(
            index_value == nullptr ? 0U : static_cast<unsigned>(index_value->getZExtValue()));
      }
      finish_value(builder,
                   context,
                   builder.CreateInsertValue(materialize_value(builder,
                                                               function_context.slot_allocas,
                                                               context.current_slot_mapping,
                                                               function_context.program,
                                                               instruction.operands[0],
                                                               function_context.opaque_seed_slot,
                                                               function_context.opaque_seed_base,
                                                               function_context.mba_context,
                                                               0x12980 + instruction_index),
                                             materialize_value(builder,
                                                               function_context.slot_allocas,
                                                               context.current_slot_mapping,
                                                               function_context.program,
                                                               instruction.operands[1],
                                                               function_context.opaque_seed_slot,
                                                               function_context.opaque_seed_base,
                                                               function_context.mba_context,
                                                               0x12990 + instruction_index),
                                             indices,
                                             "obf.vm.insert.value"));
      return true;
    }

    case opcode::gep:
    case opcode::gep_inbounds: {
      gep_handler_shape shape = select_gep_handler_shape(
          function_context, instruction, instruction_index, 0x12f00 + instruction_index);
      llvm::SmallVector<llvm::Value*, 4> indices;
      indices.reserve(instruction.operands.size() - 1);
      for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
           ++operand_index) {
        indices.push_back(materialize_value(builder,
                                            function_context.slot_allocas,
                                            context.current_slot_mapping,
                                            function_context.program,
                                            instruction.operands[operand_index],
                                            function_context.opaque_seed_slot,
                                            function_context.opaque_seed_base,
                                            function_context.mba_context,
                                            0x13000 + instruction_index * 16 + operand_index));
      }

      llvm::Value* const pointer = materialize_value(builder,
                                                     function_context.slot_allocas,
                                                     context.current_slot_mapping,
                                                     function_context.program,
                                                     instruction.operands[0],
                                                     function_context.opaque_seed_slot,
                                                     function_context.opaque_seed_base,
                                                     function_context.mba_context,
                                                     0x13100 + instruction_index);
      if ((shape == gep_handler_shape::split_index_add ||
           shape == gep_handler_shape::offset_bias) &&
          !apply_gep_index_shape(builder, indices, shape)) {
        shape = gep_handler_shape::select_equivalent_base;
      }
      llvm::Value* base_pointer = apply_gep_base_shape(builder, pointer, instruction, shape);
      llvm::Value* gep = nullptr;
      if (instruction.op == opcode::gep_inbounds) {
        gep = builder.CreateInBoundsGEP(
            const_cast<llvm::Type*>(instruction.type), base_pointer, indices, "obf.vm.gep");
      } else {
        gep = builder.CreateGEP(
            const_cast<llvm::Type*>(instruction.type), base_pointer, indices, "obf.vm.gep");
      }
      gep = tag_vm_handler_value(gep, gep_shape_marker(shape));
      finish_value(builder, context, gep);
      return true;
    }

    case opcode::memmove_fixed:
    case opcode::memcpy_fixed:
    case opcode::memset_fixed: {
      const auto emit_mem = [&](llvm::IRBuilder<>& mem_builder) {
        if (instruction.op == opcode::memset_fixed) {
          (void)mem_builder.CreateMemSet(materialize_value(mem_builder,
                                                           function_context.slot_allocas,
                                                           context.current_slot_mapping,
                                                           function_context.program,
                                                           instruction.operands[0],
                                                           function_context.opaque_seed_slot,
                                                           function_context.opaque_seed_base,
                                                           function_context.mba_context,
                                                           0x13a00 + instruction_index),
                                         materialize_value(mem_builder,
                                                           function_context.slot_allocas,
                                                           context.current_slot_mapping,
                                                           function_context.program,
                                                           instruction.operands[1],
                                                           function_context.opaque_seed_slot,
                                                           function_context.opaque_seed_base,
                                                           function_context.mba_context,
                                                           0x13a10 + instruction_index),
                                         instruction.immediate,
                                         llvm::MaybeAlign());
        } else if (instruction.op == opcode::memmove_fixed) {
          (void)mem_builder.CreateMemMove(materialize_value(mem_builder,
                                                            function_context.slot_allocas,
                                                            context.current_slot_mapping,
                                                            function_context.program,
                                                            instruction.operands[0],
                                                            function_context.opaque_seed_slot,
                                                            function_context.opaque_seed_base,
                                                            function_context.mba_context,
                                                            0x13a20 + instruction_index),
                                          llvm::MaybeAlign(),
                                          materialize_value(mem_builder,
                                                            function_context.slot_allocas,
                                                            context.current_slot_mapping,
                                                            function_context.program,
                                                            instruction.operands[1],
                                                            function_context.opaque_seed_slot,
                                                            function_context.opaque_seed_base,
                                                            function_context.mba_context,
                                                            0x13a30 + instruction_index),
                                          llvm::MaybeAlign(),
                                          instruction.immediate);
        } else {
          (void)mem_builder.CreateMemCpy(materialize_value(mem_builder,
                                                           function_context.slot_allocas,
                                                           context.current_slot_mapping,
                                                           function_context.program,
                                                           instruction.operands[0],
                                                           function_context.opaque_seed_slot,
                                                           function_context.opaque_seed_base,
                                                           function_context.mba_context,
                                                           0x13a40 + instruction_index),
                                         llvm::MaybeAlign(),
                                         materialize_value(mem_builder,
                                                           function_context.slot_allocas,
                                                           context.current_slot_mapping,
                                                           function_context.program,
                                                           instruction.operands[1],
                                                           function_context.opaque_seed_slot,
                                                           function_context.opaque_seed_base,
                                                           function_context.mba_context,
                                                           0x13a50 + instruction_index),
                                         llvm::MaybeAlign(),
                                         instruction.immediate);
        }
        if (instruction_index + 1 < function_context.slot_mappings.size()) {
          rotate_to_mapping(
              mem_builder, context, static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value* next_target = decode_target_dispatch(mem_builder,
                                                          function_context,
                                                          context.layout.fallthrough_target_offset,
                                                          0x13a60 + instruction_index);
        emit_dispatch(mem_builder,
                      function_context,
                      next_target,
                      0x13a70 + instruction_index,
                      static_cast<std::uint32_t>(instruction_index + 1));
      };
      if (select_handler_variant(instruction.op,
                                 function_context.opaque_seed_base,
                                 0x13a80 + instruction_index) == 0) {
        emit_mem(builder);
      } else {
        emit_in_helper_block(builder, context, "vm.mem.exec.", emit_mem);
      }
      return true;
    }

    default:
      return false;
  }
}

}  // namespace obf::vm
