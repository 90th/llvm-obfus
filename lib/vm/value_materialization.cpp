#include "obf/vm/virtualize_internal.h"

#include "obf/support/stable_hash.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

namespace obf::vm {

namespace {

std::uint64_t stable_hash_constant(const llvm::Constant& constant) {
  std::string printed;
  llvm::raw_string_ostream stream(printed);
  constant.printAsOperand(stream, /*PrintType=*/true);
  stream.flush();
  return stable_hash_string(printed);
}

bool should_obfuscate_vm_constant(const llvm::ConstantInt& constant) {
  if (constant.getType()->isIntegerTy(1)) { return false; }

  const llvm::APInt& value = constant.getValue();
  return !(value.isZero() || value.isOne() || value.isAllOnes());
}

llvm::Value* build_opaque_vm_mask(llvm::IRBuilder<>& builder,
                                  llvm::AllocaInst*,
                                  std::uint64_t opaque_seed_base,
                                  llvm::IntegerType* type,
                                  const llvm::APInt& key,
                                  const mba::builder_context& mba_context,
                                  std::uint64_t salt) {
  const llvm::APInt base_seed(type->getBitWidth(),
                              opaque_seed_base,
                              /*isSigned=*/false,
                              /*implicitTrunc=*/true);
  mba::builder_context seed_context = mba_context;
  seed_context.seed_base = opaque_seed_base;
  llvm::Value* typed_seed = mba::create_opaque_integer(
      builder, type, seed_context, base_seed, salt ^ 0x51f15eedULL, "obf.vm.seed");
  const llvm::APInt delta = key ^ base_seed;
  return mba::create_xor(builder,
                         typed_seed,
                         llvm::ConstantInt::get(type, delta),
                         mba_context,
                         salt,
                         "obf.vm.const.mask");
}

bool can_materialize_pointer_through_integer(const llvm::DataLayout& data_layout,
                                             const llvm::Type* type) {
  const auto* pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
  return pointer_type != nullptr &&
         !data_layout.isNonIntegralPointerType(const_cast<llvm::PointerType*>(pointer_type));
}

llvm::Value* materialize_constant(llvm::IRBuilder<>& builder,
                                  const llvm::Constant& constant,
                                  llvm::AllocaInst* opaque_seed_slot,
                                  std::uint64_t opaque_seed_base,
                                  const mba::builder_context& mba_context,
                                  std::uint64_t salt) {
  if (const auto* integer = llvm::dyn_cast<llvm::ConstantInt>(&constant)) {
    return materialize_integer_constant(
        builder, *integer, opaque_seed_slot, opaque_seed_base, mba_context, salt);
  }

  if (constant.getType()->isPointerTy()) {
    if (llvm::Value* pointer_value =
            materialize_pointer_value(builder,
                                      const_cast<llvm::Constant*>(&constant),
                                      opaque_seed_slot,
                                      opaque_seed_base,
                                      mba_context,
                                      salt ^ 0x5404ULL)) {
      return pointer_value;
    }
  }

  return const_cast<llvm::Constant*>(&constant);
}

}  // namespace

llvm::GlobalVariable* get_or_create_pointer_constant_cell(llvm::Module& module,
                                                          const llvm::Constant& constant) {
  const std::string global_name =
      ("__obf_vm_ptrconst_" + llvm::utohexstr(stable_hash_constant(constant)));
  if (llvm::GlobalVariable* existing = module.getNamedGlobal(global_name)) {
    if (existing->getValueType() != constant.getType()) {
      llvm_unreachable("vm pointer constant cell has unexpected type");
    }
    return existing;
  }

  auto* cell = new llvm::GlobalVariable(module,
                                        const_cast<llvm::Type*>(constant.getType()),
                                        /*isConstant=*/true,
                                        llvm::GlobalValue::PrivateLinkage,
                                        const_cast<llvm::Constant*>(&constant),
                                        global_name);
  cell->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  return cell;
}

llvm::Value* load_slot(llvm::IRBuilder<>& builder,
                       const slot_storage& slot_allocas,
                       llvm::ArrayRef<std::uint32_t> slot_mapping,
                       const bytecode_program& program,
                       std::uint32_t slot,
                       const mba::builder_context& mba_context,
                       std::uint64_t salt) {
  const slot_desc& slot_info = program.slots[slot];
  llvm::Value* slot_address = slot_allocas[slot][slot_mapping[slot]];
  if (slot_info.type->isPointerTy()) {
    if (llvm::Value* pointer_value =
            load_pointer_value_from_memory(builder,
                                           slot_address,
                                           const_cast<llvm::Type*>(slot_info.type),
                                           mba_context,
                                           salt ^ 0x5c0cULL,
                                           llvm::MaybeAlign(),
                                           "obf.vm.slot.ptr")) {
      return pointer_value;
    }
  }

  return builder.CreateLoad(const_cast<llvm::Type*>(slot_info.type), slot_address, "obf.vm.slot");
}

void store_slot(llvm::IRBuilder<>& builder,
                const slot_storage& slot_allocas,
                llvm::ArrayRef<std::uint32_t> slot_mapping,
                const bytecode_program& program,
                std::uint32_t slot,
                llvm::Value* value,
                llvm::AllocaInst* opaque_seed_slot,
                std::uint64_t opaque_seed_base,
                const mba::builder_context& mba_context,
                std::uint64_t salt) {
  const slot_desc& slot_info = program.slots[slot];
  llvm::Value* slot_address = slot_allocas[slot][slot_mapping[slot]];
  if (slot_info.type->isPointerTy()) {
    if (store_pointer_value_to_memory(builder,
                                      slot_address,
                                      value,
                                      const_cast<llvm::Type*>(slot_info.type),
                                      opaque_seed_slot,
                                      opaque_seed_base,
                                      mba_context,
                                      salt ^ 0x5d0dULL)) {
      return;
    }
  }

  builder.CreateStore(value, slot_address);
}

void rotate_slot_cells(llvm::IRBuilder<>& builder,
                       const slot_storage& slot_allocas,
                       const bytecode_program& program,
                       llvm::ArrayRef<std::uint32_t> current_mapping,
                       llvm::ArrayRef<std::uint32_t> target_mapping,
                       const mba::builder_context& mba_context,
                       std::uint64_t salt) {
  struct pending_slot_move {
    std::uint32_t slot = invalid_slot;
    llvm::Value* value = nullptr;
    bool uses_pointer_carrier = false;
  };

  llvm::SmallVector<pending_slot_move, 16> pending_moves;
  pending_moves.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    if (current_mapping[slot_index] == target_mapping[slot_index]) { continue; }

    const slot_desc& slot_info = program.slots[slot_index];
    if (slot_info.type->isPointerTy()) {
      if (llvm::Value* carrier = load_pointer_carrier_from_memory(
              builder,
              slot_allocas[slot_index][current_mapping[slot_index]],
              const_cast<llvm::Type*>(slot_info.type),
              mba_context,
              salt + static_cast<std::uint64_t>(slot_index) * 4 + 1,
              llvm::MaybeAlign(),
              "obf.vm.rot.ptr")) {
        pending_moves.push_back({.slot = static_cast<std::uint32_t>(slot_index),
                                 .value = carrier,
                                 .uses_pointer_carrier = true});
        continue;
      }
    }

    pending_moves.push_back(
        {.slot = static_cast<std::uint32_t>(slot_index),
         .value = builder.CreateLoad(const_cast<llvm::Type*>(slot_info.type),
                                     slot_allocas[slot_index][current_mapping[slot_index]],
                                     "obf.vm.rot.load")});
  }

  for (const pending_slot_move& move : pending_moves) {
    if (move.uses_pointer_carrier) {
      llvm::Type* pointer_type = const_cast<llvm::Type*>(program.slots[move.slot].type);
      if (store_pointer_carrier_to_memory(builder,
                                          slot_allocas[move.slot][target_mapping[move.slot]],
                                          move.value,
                                          pointer_type,
                                          mba_context,
                                          salt + static_cast<std::uint64_t>(move.slot) * 4 + 2)) {
        if (auto* carrier_type = get_pointer_carrier_type(builder, pointer_type)) {
          (void)store_pointer_carrier_to_memory(builder,
                                                slot_allocas[move.slot][current_mapping[move.slot]],
                                                llvm::ConstantInt::get(carrier_type, 0),
                                                pointer_type,
                                                mba_context,
                                                salt + static_cast<std::uint64_t>(move.slot) * 4 +
                                                    3);
        }
        continue;
      }
    }

    builder.CreateStore(move.value, slot_allocas[move.slot][target_mapping[move.slot]]);
    builder.CreateStore(
        llvm::Constant::getNullValue(const_cast<llvm::Type*>(program.slots[move.slot].type)),
        slot_allocas[move.slot][current_mapping[move.slot]]);
  }
}

llvm::Value* materialize_integer_constant(llvm::IRBuilder<>& builder,
                                          const llvm::ConstantInt& integer,
                                          llvm::AllocaInst* opaque_seed_slot,
                                          std::uint64_t opaque_seed_base,
                                          const mba::builder_context& mba_context,
                                          std::uint64_t salt) {
  if (!should_obfuscate_vm_constant(integer)) { return const_cast<llvm::ConstantInt*>(&integer); }

  const llvm::APInt& value = integer.getValue();
  const std::uint64_t constant_salt = static_cast<std::uint64_t>(value.getBitWidth()) * 131ULL;
  const std::uint64_t word = value.getLimitedValue();
  const llvm::APInt key(value.getBitWidth(),
                        (word ^ 0x9e3779b97f4a7c15ULL) + constant_salt,
                        /*isSigned=*/false,
                        /*implicitTrunc=*/true);
  const llvm::APInt encoded = value ^ key;
  llvm::Value* mask = build_opaque_vm_mask(builder,
                                           opaque_seed_slot,
                                           opaque_seed_base,
                                           llvm::cast<llvm::IntegerType>(integer.getType()),
                                           key,
                                           mba_context,
                                           salt ^ constant_salt ^ 0x13579bdfULL);
  return mba::create_xor(builder,
                         llvm::ConstantInt::get(integer.getType(), encoded),
                         mask,
                         mba_context,
                         salt ^ constant_salt ^ 0x2468ace0ULL,
                         "obf.vm.const");
}

const llvm::DataLayout* get_builder_data_layout(const llvm::IRBuilder<>& builder) {
  const llvm::BasicBlock* block = builder.GetInsertBlock();
  const llvm::Function* function = block != nullptr ? block->getParent() : nullptr;
  const llvm::Module* module = function != nullptr ? function->getParent() : nullptr;
  return module != nullptr ? &module->getDataLayout() : nullptr;
}

llvm::IntegerType* get_pointer_carrier_type(llvm::IRBuilder<>& builder, llvm::Type* type) {
  const llvm::DataLayout* data_layout = get_builder_data_layout(builder);
  if (data_layout == nullptr || !can_materialize_pointer_through_integer(*data_layout, type)) {
    return nullptr;
  }

  const auto* pointer_type = llvm::cast<llvm::PointerType>(type);
  return data_layout->getIntPtrType(builder.getContext(), pointer_type->getAddressSpace());
}

llvm::Value* materialize_pointer_carrier(llvm::IRBuilder<>& builder,
                                         llvm::Value* pointer_value,
                                         llvm::AllocaInst* opaque_seed_slot,
                                         std::uint64_t opaque_seed_base,
                                         const mba::builder_context& mba_context,
                                         std::uint64_t salt) {
  auto* carrier_type = get_pointer_carrier_type(builder, pointer_value->getType());
  if (carrier_type == nullptr) { return nullptr; }

  if (const auto* pointer_constant = llvm::dyn_cast<llvm::Constant>(pointer_value)) {
    llvm::BasicBlock* block = builder.GetInsertBlock();
    llvm::Function* function = block != nullptr ? block->getParent() : nullptr;
    llvm::Module* module = function != nullptr ? function->getParent() : nullptr;
    if (module != nullptr) {
      llvm::GlobalVariable* pointer_cell =
          get_or_create_pointer_constant_cell(*module, *pointer_constant);
      pointer_value = builder.CreateLoad(
          const_cast<llvm::Type*>(pointer_constant->getType()), pointer_cell, "obf.vm.ptr.const");
    }
  }

  llvm::Value* raw_carrier = builder.CreatePtrToInt(pointer_value, carrier_type, "obf.vm.ptr.raw");
  if (const auto* carrier_integer = llvm::dyn_cast<llvm::ConstantInt>(raw_carrier)) {
    return materialize_integer_constant(builder,
                                        *carrier_integer,
                                        opaque_seed_slot,
                                        opaque_seed_base,
                                        mba_context,
                                        salt ^ 0x5101ULL);
  }

  return mba::entangle_value(
      builder, raw_carrier, mba_context, salt ^ 0x5202ULL, "obf.vm.ptr.carrier");
}

llvm::Value* materialize_pointer_value(llvm::IRBuilder<>& builder,
                                       llvm::Value* pointer_value,
                                       llvm::AllocaInst* opaque_seed_slot,
                                       std::uint64_t opaque_seed_base,
                                       const mba::builder_context& mba_context,
                                       std::uint64_t salt) {
  auto* pointer_type = llvm::dyn_cast<llvm::PointerType>(pointer_value->getType());
  if (pointer_type == nullptr) { return nullptr; }

  llvm::Value* carrier = materialize_pointer_carrier(
      builder, pointer_value, opaque_seed_slot, opaque_seed_base, mba_context, salt ^ 0x5303ULL);
  if (carrier == nullptr) { return nullptr; }

  return builder.CreateIntToPtr(carrier, pointer_type, "obf.vm.ptr");
}

llvm::Value* load_pointer_carrier_from_memory(llvm::IRBuilder<>& builder,
                                              llvm::Value* address,
                                              llvm::Type* pointer_type,
                                              const mba::builder_context& mba_context,
                                              std::uint64_t salt,
                                              llvm::MaybeAlign alignment,
                                              llvm::StringRef name_prefix) {
  auto* carrier_type = get_pointer_carrier_type(builder, pointer_type);
  if (carrier_type == nullptr) { return nullptr; }

  const std::string base_name = name_prefix.empty() ? "obf.vm.ptr.load" : name_prefix.str();
  auto* load = builder.CreateLoad(carrier_type, address, base_name + ".raw");
  if (alignment) { load->setAlignment(*alignment); }

  llvm::Value* carrier =
      emit_unsigned_integer_width_cast(builder, load, carrier_type, mba_context, salt + 1);
  return carrier != nullptr ? carrier : load;
}

llvm::Value* load_pointer_value_from_memory(llvm::IRBuilder<>& builder,
                                            llvm::Value* address,
                                            llvm::Type* pointer_type,
                                            const mba::builder_context& mba_context,
                                            std::uint64_t salt,
                                            llvm::MaybeAlign alignment,
                                            llvm::StringRef name_prefix) {
  auto* typed_pointer = llvm::dyn_cast<llvm::PointerType>(pointer_type);
  if (typed_pointer == nullptr) { return nullptr; }

  llvm::Value* carrier = load_pointer_carrier_from_memory(
      builder, address, pointer_type, mba_context, salt, alignment, name_prefix);
  if (carrier == nullptr) { return nullptr; }

  const std::string base_name = name_prefix.empty() ? "obf.vm.ptr.load" : name_prefix.str();
  return builder.CreateIntToPtr(carrier, typed_pointer, base_name + ".value");
}

llvm::StoreInst* store_pointer_carrier_to_memory(llvm::IRBuilder<>& builder,
                                                 llvm::Value* address,
                                                 llvm::Value* carrier,
                                                 llvm::Type* pointer_type,
                                                 const mba::builder_context& mba_context,
                                                 std::uint64_t salt,
                                                 llvm::MaybeAlign alignment) {
  auto* carrier_type = get_pointer_carrier_type(builder, pointer_type);
  if (carrier_type == nullptr) { return nullptr; }

  llvm::Value* normalized =
      emit_unsigned_integer_width_cast(builder, carrier, carrier_type, mba_context, salt + 1);
  if (normalized == nullptr) { return nullptr; }

  auto* store = builder.CreateStore(normalized, address);
  if (alignment) { store->setAlignment(*alignment); }
  return store;
}

llvm::StoreInst* store_pointer_value_to_memory(llvm::IRBuilder<>& builder,
                                               llvm::Value* address,
                                               llvm::Value* pointer_value,
                                               llvm::Type* pointer_type,
                                               llvm::AllocaInst* opaque_seed_slot,
                                               std::uint64_t opaque_seed_base,
                                               const mba::builder_context& mba_context,
                                               std::uint64_t salt,
                                               llvm::MaybeAlign alignment) {
  llvm::Value* carrier = materialize_pointer_carrier(
      builder, pointer_value, opaque_seed_slot, opaque_seed_base, mba_context, salt ^ 0x5a0aULL);
  if (carrier == nullptr) { return nullptr; }

  return store_pointer_carrier_to_memory(
      builder, address, carrier, pointer_type, mba_context, salt ^ 0x5b0bULL, alignment);
}

llvm::Value* materialize_value(llvm::IRBuilder<>& builder,
                               const slot_storage& slot_allocas,
                               llvm::ArrayRef<std::uint32_t> slot_mapping,
                               const bytecode_program& program,
                               const value_ref& value,
                               llvm::AllocaInst* opaque_seed_slot,
                               std::uint64_t opaque_seed_base,
                               const mba::builder_context& mba_context,
                               std::uint64_t salt) {
  if (value.kind == value_ref_kind::slot) {
    llvm::Value* slot_value = load_slot(
        builder, slot_allocas, slot_mapping, program, value.slot, mba_context, salt ^ 0x5505ULL);
    return slot_value;
  }

  return materialize_constant(
      builder, *value.constant, opaque_seed_slot, opaque_seed_base, mba_context, salt);
}

const llvm::Type* value_ref_type(const bytecode_program& program, const value_ref& value) {
  if (value.kind == value_ref_kind::slot) { return program.slots[value.slot].type; }

  return value.constant->getType();
}

llvm::Value* materialize_pointer_carrier_from_value_ref(llvm::IRBuilder<>& builder,
                                                        const slot_storage& slot_allocas,
                                                        llvm::ArrayRef<std::uint32_t> slot_mapping,
                                                        const bytecode_program& program,
                                                        const value_ref& value,
                                                        llvm::AllocaInst* opaque_seed_slot,
                                                        std::uint64_t opaque_seed_base,
                                                        const mba::builder_context& mba_context,
                                                        std::uint64_t salt) {
  if (!value_ref_type(program, value)->isPointerTy()) { return nullptr; }

  llvm::Value* pointer_value = nullptr;
  if (value.kind == value_ref_kind::slot) {
    const slot_desc& slot_info = program.slots[value.slot];
    if (llvm::Value* carrier =
            load_pointer_carrier_from_memory(builder,
                                             slot_allocas[value.slot][slot_mapping[value.slot]],
                                             const_cast<llvm::Type*>(slot_info.type),
                                             mba_context,
                                             salt ^ 0x5606ULL,
                                             llvm::MaybeAlign(),
                                             "obf.vm.ptr.slot")) {
      return carrier;
    }

    pointer_value = load_slot(
        builder, slot_allocas, slot_mapping, program, value.slot, mba_context, salt ^ 0x5707ULL);
  } else {
    pointer_value = const_cast<llvm::Constant*>(value.constant);
  }

  return materialize_pointer_carrier(
      builder, pointer_value, opaque_seed_slot, opaque_seed_base, mba_context, salt);
}

}  // namespace obf::vm
