#include "obf/vm/virtualize_internal.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/IR/Constants.h"

#include <algorithm>
#include <array>
#include <limits>
#include <numeric>
#include <random>
#include <string>

namespace obf::vm {

namespace {

std::mt19937 build_opcode_rng(const llvm::Function &function,
                             const bytecode_program &program) {
  const std::uint64_t seed_base = mix_seed(derive_vm_bytecode_seed(function, program),
                                           0x0f4c0d3aa19b27d5ULL);
  std::seed_seq seed_words{
      static_cast<std::uint32_t>(seed_base),
      static_cast<std::uint32_t>(seed_base >> 32),
      static_cast<std::uint32_t>(llvm::hash_value(function.getName())),
      static_cast<std::uint32_t>(program.instructions.size())};
  return std::mt19937(seed_words);
}

llvm::Value *build_dispatch_key(llvm::IRBuilder<> &builder,
                                rewrite_function_context &context,
                                llvm::Value *dispatch_index,
                                std::uint64_t salt) {
  llvm::Value *typed_seed = nullptr;
  if (context.hidden_token_arg != nullptr) {
    typed_seed = context.hidden_token_arg;
    if (typed_seed->getType() != context.ptr_int_type) {
      typed_seed = builder.CreateZExtOrTrunc(typed_seed, context.ptr_int_type,
                                             "obf.vm.dispatch.seed.cast");
    }
    typed_seed = mba::entangle_value(builder, typed_seed, context.mba_context,
                                     salt ^ 0x7000ULL,
                                     "obf.vm.dispatch.seed");
  } else {
    typed_seed = mba::create_opaque_integer(
        builder, context.ptr_int_type, context.mba_context,
        llvm::APInt(context.ptr_int_type->getBitWidth(), context.opaque_seed_base,
                    /*isSigned=*/false, /*implicitTrunc=*/true),
        salt ^ 0x7000ULL, "obf.vm.dispatch.seed");
  }

  llvm::Value *typed_index = dispatch_index;
  if (typed_index->getType() != context.ptr_int_type) {
    typed_index = builder.CreateZExt(typed_index, context.ptr_int_type,
                                     "obf.vm.dispatch.index.cast");
  }

  llvm::Value *seed_mix = mba::create_xor(
      builder, typed_seed,
      llvm::ConstantInt::get(context.ptr_int_type,
                             mix_seed(context.bytecode_seed, 0x7001ULL)),
      context.mba_context, salt + 1, "obf.vm.dispatch.seed.mix");
  llvm::Value *index_mix = mba::create_add(
      builder, typed_index,
      llvm::ConstantInt::get(context.ptr_int_type,
                             mix_seed(context.bytecode_seed, 0x7002ULL)),
      context.mba_context, salt + 2, "obf.vm.dispatch.index.mix");
  return mba::create_xor(builder, seed_mix, index_mix, context.mba_context,
                         salt + 3, "obf.vm.dispatch.key");
}

std::uint32_t build_switch_site_multiplier(std::uint64_t bytecode_seed,
                                           std::uint64_t salt) {
  std::uint32_t multiplier = static_cast<std::uint32_t>(
      mix_seed(bytecode_seed, 0x5357495443482001ULL ^ salt));
  multiplier |= 1U;
  if (multiplier == 1U) {
    multiplier = 0x9e3779b1U;
  }
  return multiplier;
}

std::uint32_t build_switch_site_offset(std::uint64_t bytecode_seed,
                                       std::uint64_t salt) {
  return static_cast<std::uint32_t>(
      mix_seed(bytecode_seed, 0x5357495443482002ULL ^ salt));
}

std::uint32_t remap_switch_dispatch_constant(std::uint64_t bytecode_seed,
                                             std::uint32_t dispatch_index,
                                             std::uint64_t salt) {
  const std::uint32_t multiplier =
      build_switch_site_multiplier(bytecode_seed, salt);
  const std::uint32_t offset = build_switch_site_offset(bytecode_seed, salt);
  return static_cast<std::uint32_t>(
      static_cast<std::uint64_t>(dispatch_index) * multiplier + offset);
}

llvm::Value *remap_switch_dispatch_value(llvm::IRBuilder<> &builder,
                                         std::uint64_t bytecode_seed,
                                         llvm::Value *dispatch_index,
                                         std::uint64_t salt) {
  const std::uint32_t multiplier =
      build_switch_site_multiplier(bytecode_seed, salt);
  const std::uint32_t offset = build_switch_site_offset(bytecode_seed, salt);
  llvm::Value *remapped = builder.CreateMul(
      dispatch_index, builder.getInt32(multiplier),
      "obf.vm.dispatch.index.site.mul");
  return builder.CreateAdd(remapped, builder.getInt32(offset),
                           "obf.vm.dispatch.index.site");
}

} // namespace

std::uint32_t select_dispatch_variant(std::uint64_t seed_base, std::uint64_t salt,
                                      std::size_t instruction_count,
                                      std::uint32_t variant_count) {
  if (variant_count <= 1 ||
      instruction_count >= vm_switch_dispatch_min_instruction_count) {
    return static_cast<std::uint32_t>(dispatch_backend_variant::switch_index);
  }

  const std::uint32_t fallback_variant_count = variant_count - 1;
  if (fallback_variant_count == 0) {
    return static_cast<std::uint32_t>(dispatch_backend_variant::switch_index);
  }

  return 1 + static_cast<std::uint32_t>(
                 mix_seed(seed_base, salt ^ 0xd15f57a5a93ULL) %
                 fallback_variant_count);
}

vm_dispatcher_shape select_dispatcher_shape(std::uint64_t seed_base,
                                            std::uint64_t salt,
                                            std::size_t instruction_count) {
  if (instruction_count < vm_switch_dispatch_min_instruction_count) {
    return vm_dispatcher_shape::direct_threaded;
  }

  const std::uint64_t choice = mix_seed(
      seed_base, salt ^ (static_cast<std::uint64_t>(instruction_count) *
                         0x9e3779b97f4a7c15ULL));
  return (choice & 1ULL) == 0 ? vm_dispatcher_shape::switch_biased
                              : vm_dispatcher_shape::banked;
}

std::uint32_t select_switch_dispatch_bank_count(std::uint64_t seed_base,
                                                std::uint64_t salt,
                                                std::size_t instruction_count,
                                                vm_dispatcher_shape shape) {
  if (shape == vm_dispatcher_shape::switch_biased || instruction_count < 8) {
    return 1;
  }
  if (shape != vm_dispatcher_shape::banked) {
    return 0;
  }

  const std::uint32_t max_bank_count = static_cast<std::uint32_t>(
      std::min<std::size_t>(switch_dispatch_max_bank_count,
                            std::max<std::size_t>(2, instruction_count / 4)));
  return 2U + static_cast<std::uint32_t>(
                 mix_seed(seed_base, salt ^ 0xba11d15fULL) %
                 (max_bank_count - 1U));
}

vm_island_topology select_vm_island_topology(bool prefer_islands,
                                              std::size_t instruction_count,
                                              std::uint64_t seed_base,
                                              std::uint64_t salt) {
  if (!prefer_islands || instruction_count < vm_island_min_instruction_count) {
    return vm_island_topology::none;
  }
  if (instruction_count < vm_island_min_instruction_count + 8) {
    const std::uint64_t choice = mix_seed(
        seed_base, salt ^ (static_cast<std::uint64_t>(instruction_count) *
                           0x151a151a151a151aULL));
    if ((choice & 1ULL) != 0) {
      return vm_island_topology::none;
    }
  }
  return vm_island_topology::helper_shards;
}

std::uint32_t select_vm_island_count(std::uint64_t seed_base,
                                     std::uint64_t salt,
                                     std::size_t instruction_count,
                                     vm_island_topology topology) {
  if (topology != vm_island_topology::helper_shards) {
    return 0;
  }
  const std::uint32_t base_count = 3U;
  const std::uint32_t max_count = static_cast<std::uint32_t>(
      std::min<std::size_t>(vm_island_max_count,
                            std::max<std::size_t>(base_count,
                                                  instruction_count / 16)));
  if (max_count <= base_count) {
    return base_count;
  }
  return base_count + static_cast<std::uint32_t>(
                          mix_seed(seed_base, salt ^ 0x151a9dULL) %
                          (max_count - base_count + 1U));
}

opcode_permutation build_opcode_permutation(const llvm::Function &function,
                                            const bytecode_program &program) {
  opcode_permutation permutation;
  std::array<std::uint8_t, 256> physical_values = {};
  std::iota(physical_values.begin(), physical_values.end(), 0);

  std::mt19937 rng = build_opcode_rng(function, program);
  std::shuffle(physical_values.begin(), physical_values.end(), rng);
  for (std::size_t logical_index = 0; logical_index < vm_opcode_count;
       ++logical_index) {
    permutation.physical_for_logical[logical_index] = physical_values[logical_index];
  }

  return permutation;
}

std::uint8_t get_physical_opcode(const opcode_permutation &permutation,
                                 opcode logical_opcode) {
  return permutation.physical_for_logical[opcode_to_index(logical_opcode)];
}

std::vector<slot_cell_mapping>
build_slot_cell_mappings(const bytecode_program &program, std::uint64_t seed_base) {
  std::vector<slot_cell_mapping> mappings;
  mappings.reserve(program.instructions.size());
  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    slot_cell_mapping mapping(program.slots.size(), 0);
    for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
      const std::uint64_t slot_seed =
          mix_seed(seed_base, static_cast<std::uint64_t>(slot_index + 1) *
                                  0x100000001b3ULL);
      const std::uint32_t base_cell =
          static_cast<std::uint32_t>(slot_seed % vm_slot_rotation_cell_count);
      const std::uint32_t step = 1U + static_cast<std::uint32_t>(
                                            mix_seed(slot_seed, 0x6a09e667f3bcc909ULL) %
                                            (vm_slot_rotation_cell_count - 1));
      mapping[slot_index] = static_cast<std::uint32_t>(
          (base_cell + (static_cast<std::uint64_t>(instruction_index + 1) * step)) %
          vm_slot_rotation_cell_count);
    }
    mappings.push_back(std::move(mapping));
  }

  return mappings;
}

std::vector<std::uint32_t>
build_dispatch_index_map(const bytecode_program &program, std::uint64_t seed,
                         dispatch_backend_variant dispatch_backend) {
  std::vector<std::uint32_t> order(program.instructions.size());
  std::iota(order.begin(), order.end(), 0U);
  std::stable_sort(order.begin(), order.end(), [&](std::uint32_t lhs,
                                                   std::uint32_t rhs) {
    const std::uint64_t lhs_key = mix_seed(seed, lhs + 1);
    const std::uint64_t rhs_key = mix_seed(seed, rhs + 1);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  std::vector<std::uint32_t> dispatch_index_for_instruction(order.size(), 0);
  if (dispatch_backend != dispatch_backend_variant::switch_index) {
    for (std::uint32_t dispatch_index = 0; dispatch_index < order.size();
         ++dispatch_index) {
      dispatch_index_for_instruction[order[dispatch_index]] = dispatch_index;
    }
    return dispatch_index_for_instruction;
  }

  if (order.empty()) {
    return dispatch_index_for_instruction;
  }

  const std::uint64_t key_budget = std::max<std::uint64_t>(
      2ULL, std::numeric_limits<std::uint32_t>::max() /
                static_cast<std::uint64_t>(order.size()));
  std::uint64_t current_key =
      1ULL + (mix_seed(seed, 0x5357495443480001ULL) % key_budget);
  dispatch_index_for_instruction[order.front()] =
      static_cast<std::uint32_t>(current_key);
  for (std::size_t key_index = 1; key_index < order.size(); ++key_index) {
    const std::uint64_t gap =
        1ULL +
        (mix_seed(seed, 0x5357495443481000ULL ^
                            (static_cast<std::uint64_t>(key_index) *
                             0x9e3779b97f4a7c15ULL)) %
         key_budget);
    current_key += gap;
    dispatch_index_for_instruction[order[key_index]] =
        static_cast<std::uint32_t>(current_key);
  }

  return dispatch_index_for_instruction;
}

std::vector<std::uint64_t>
build_instruction_entry_states(const bytecode_program &program, std::uint64_t seed) {
  std::vector<std::uint64_t> entry_states(program.instructions.size(), 0);
  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    std::uint64_t state =
        mix_seed(seed, static_cast<std::uint64_t>(instruction_index + 1));
    if (state == 0) {
      state = 0x7f4a7c159e3779b9ULL ^ static_cast<std::uint64_t>(instruction_index);
    }
    entry_states[instruction_index] = state;
  }

  return entry_states;
}

void initialize_dispatch_runtime(llvm::IRBuilder<> &entry_builder,
                                 rewrite_function_context &context) {
  if (!context.instruction_blocks.empty() &&
      context.dispatch_backend == dispatch_backend_variant::switch_index) {
    const std::uint32_t bank_count =
        std::max<std::uint32_t>(1, context.switch_dispatch_bank_count);
    context.switch_dispatch_banks.reserve(bank_count);
    llvm::SmallVector<std::uint32_t, switch_dispatch_max_bank_count> bank_order;
    bank_order.reserve(bank_count);
    for (std::uint32_t bank_index = 0; bank_index < bank_count; ++bank_index) {
      bank_order.push_back(bank_index);
    }
    std::stable_sort(bank_order.begin(), bank_order.end(), [&](std::uint32_t lhs,
                                                               std::uint32_t rhs) {
      const std::uint64_t lhs_key = mix_seed(context.bytecode_seed,
                                            0xba110000ULL + lhs);
      const std::uint64_t rhs_key = mix_seed(context.bytecode_seed,
                                            0xba110000ULL + rhs);
      return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
    });

    for (std::size_t bank_position = 0; bank_position < bank_order.size();
         ++bank_position) {
      const std::uint32_t bank_index = bank_order[bank_position];
      const std::uint64_t bank_salt = 0x177000ULL + bank_index;
      const bool is_banked_shape =
          context.dispatch_shape == vm_dispatcher_shape::banked;
      const std::string shape_name =
          is_banked_shape ? "vm.dispatch.shape.banked.vm.dispatch.bank"
                          : "vm.dispatch.shape.switch.vm.dispatch.switch";
      auto *dispatch_switch_block = llvm::BasicBlock::Create(
          context.function.getContext(),
          shape_name + "." + std::to_string(bank_index),
          &context.function);
      llvm::IRBuilder<> switch_builder(dispatch_switch_block);
      auto *dispatch_index_phi = switch_builder.CreatePHI(
          switch_builder.getInt32Ty(), 8, "obf.vm.dispatch.index.bank");
      llvm::Value *remapped_dispatch_index = remap_switch_dispatch_value(
          switch_builder, context.bytecode_seed, dispatch_index_phi, bank_salt);
      auto *switch_inst = switch_builder.CreateSwitch(
          remapped_dispatch_index, context.trap_block,
          context.instruction_blocks.size());
      for (std::size_t instruction_index = 0;
           instruction_index < context.instruction_blocks.size();
           ++instruction_index) {
        const std::uint32_t dispatch_index =
            context.dispatch_index_for_instruction[instruction_index];
        switch_inst->addCase(
            switch_builder.getInt32(remap_switch_dispatch_constant(
                context.bytecode_seed, dispatch_index, bank_salt)),
            context.instruction_blocks[instruction_index]);
      }
      context.switch_dispatch_banks.push_back(
          {.block = dispatch_switch_block,
           .dispatch_index_phi = dispatch_index_phi,
           .switch_inst = switch_inst,
           .salt = bank_salt});
    }
  }

  if (!context.instruction_blocks.empty() && context.dispatch_table != nullptr) {
    for (std::size_t instruction_index = 0;
         instruction_index < context.instruction_blocks.size(); ++instruction_index) {
      const std::uint32_t dispatch_index =
          context.dispatch_index_for_instruction[instruction_index];
      llvm::Value *slot = entry_builder.CreateInBoundsGEP(
          context.dispatch_table_type, context.dispatch_table,
          {entry_builder.getInt32(0), entry_builder.getInt32(dispatch_index)},
          "obf.vm.dispatch.slot." + std::to_string(dispatch_index));
      llvm::Value *plain_target = entry_builder.CreatePtrToInt(
          llvm::BlockAddress::get(&context.function,
                                  context.instruction_blocks[instruction_index]),
          context.ptr_int_type,
          "obf.vm.dispatch.addr." + std::to_string(dispatch_index));
      llvm::Value *key = build_dispatch_key(
          entry_builder, context, entry_builder.getInt32(dispatch_index),
          0x4000 + dispatch_index);
      llvm::Value *encoded_target = mba::create_xor(
          entry_builder, plain_target, key, context.mba_context,
          0x5000 + dispatch_index,
          "obf.vm.dispatch.enc." + std::to_string(dispatch_index));
      entry_builder.CreateStore(encoded_target, slot);
    }
  }
}

void emit_dispatch(llvm::IRBuilder<> &builder,
                   rewrite_function_context &context,
                   llvm::Value *dispatch_index, std::uint64_t salt,
                   std::uint32_t target_instruction) {
  if (context.state_island_body) {
    if (context.dispatch_index_slot == nullptr || context.island_id_slot == nullptr ||
        target_instruction >= context.island_for_instruction.size()) {
      builder.CreateRet(builder.getInt32(vm_island_trap_status));
      return;
    }
    llvm::Value *typed_dispatch_index = dispatch_index;
    if (typed_dispatch_index->getType() != builder.getInt32Ty()) {
      typed_dispatch_index = builder.CreateZExtOrTrunc(
          typed_dispatch_index, builder.getInt32Ty(), "obf.vm.island.dispatch.cast");
    }
    builder.CreateStore(typed_dispatch_index, context.dispatch_index_slot);
    builder.CreateStore(
        builder.getInt32(context.island_for_instruction[target_instruction]),
        context.island_id_slot);
    builder.CreateRet(builder.getInt32(vm_island_continue_status));
    return;
  }

  if (context.dispatch_backend == dispatch_backend_variant::switch_index) {
    if (context.switch_dispatch_banks.empty()) {
      builder.CreateBr(context.trap_block);
      return;
    }

    llvm::BasicBlock *dispatch_source = builder.GetInsertBlock();
    std::size_t bank_index = 0;
    if (context.dispatch_shape == vm_dispatcher_shape::banked) {
      if (auto *constant_index = llvm::dyn_cast<llvm::ConstantInt>(dispatch_index)) {
        const std::uint32_t bank_id = static_cast<std::uint32_t>(
            constant_index->getZExtValue() % context.switch_dispatch_banks.size());
        for (std::size_t index = 0; index < context.switch_dispatch_banks.size();
             ++index) {
          if ((context.switch_dispatch_banks[index].salt - 0x177000ULL) == bank_id) {
            bank_index = index;
            break;
          }
        }
      } else {
        bank_index = static_cast<std::size_t>(
            mix_seed(context.bytecode_seed, 0x5357495443483003ULL ^ salt) %
            context.switch_dispatch_banks.size());
      }
    }
    switch_dispatch_bank &bank = context.switch_dispatch_banks[bank_index];
    builder.CreateBr(bank.block);
    bank.dispatch_index_phi->addIncoming(dispatch_index, dispatch_source);
    return;
  }

  llvm::Value *in_range = builder.CreateICmpULT(
      dispatch_index,
      builder.getInt32(static_cast<std::uint32_t>(context.instruction_blocks.size())),
      "obf.vm.dispatch.inrange");

  auto *jump_block = llvm::BasicBlock::Create(
      context.function.getContext(),
      "vm.dispatch.shape.direct.dispatch.jump.obf.vm." +
          std::to_string(context.dispatch_site_counter++),
      &context.function);
  builder.CreateCondBr(in_range, jump_block, context.trap_block);

  llvm::IRBuilder<> jump_builder(jump_block);
  llvm::Value *dispatch_slot = jump_builder.CreateInBoundsGEP(
      context.dispatch_table_type, context.dispatch_table,
      {jump_builder.getInt32(0), dispatch_index}, "obf.vm.dispatch.slot");
  auto *encoded_target = jump_builder.CreateLoad(context.ptr_int_type, dispatch_slot,
                                                 "obf.vm.dispatch.encoded");
  llvm::Value *key = build_dispatch_key(jump_builder, context, dispatch_index, salt);
  llvm::Value *decoded_target = mba::create_xor(
      jump_builder, encoded_target, key, context.mba_context, salt + 1,
      "obf.vm.dispatch.target.int");

  if (context.dispatch_backend == dispatch_backend_variant::direct_threaded_match) {
    llvm::Value *dispatch_target = nullptr;
    llvm::Value *target_match = nullptr;
    for (llvm::BasicBlock *instruction_block : context.instruction_blocks) {
      llvm::Constant *plain_target = llvm::ConstantExpr::getPtrToInt(
          llvm::BlockAddress::get(&context.function, instruction_block),
          context.ptr_int_type);
      llvm::Value *is_match = jump_builder.CreateICmpEQ(
          decoded_target, plain_target, "obf.vm.dispatch.match");
      if (dispatch_target == nullptr) {
        dispatch_target = llvm::BlockAddress::get(&context.function, instruction_block);
        target_match = is_match;
        continue;
      }

      target_match =
          jump_builder.CreateOr(target_match, is_match, "obf.vm.dispatch.any");
      dispatch_target = jump_builder.CreateSelect(
          is_match, llvm::BlockAddress::get(&context.function, instruction_block),
          dispatch_target, "obf.vm.dispatch.target");
    }

    auto *emit_block = llvm::BasicBlock::Create(
        context.function.getContext(),
        "dispatch.emit.obf.vm." + std::to_string(context.dispatch_site_counter++),
        &context.function);
    jump_builder.CreateCondBr(target_match, emit_block, context.trap_block);

    llvm::IRBuilder<> emit_builder(emit_block);
    auto *dispatch =
        emit_builder.CreateIndirectBr(dispatch_target, context.instruction_blocks.size());
    for (llvm::BasicBlock *instruction_block : context.instruction_blocks) {
      dispatch->addDestination(instruction_block);
    }
    return;
  }

  auto *dispatch_switch_block = llvm::BasicBlock::Create(
      context.function.getContext(),
      "dispatch.switch.obf.vm." + std::to_string(context.dispatch_site_counter++),
      &context.function);
  jump_builder.CreateBr(dispatch_switch_block);

  llvm::IRBuilder<> switch_builder(dispatch_switch_block);
  auto *emit_block = llvm::BasicBlock::Create(
      context.function.getContext(),
      "dispatch.emit.obf.vm." + std::to_string(context.dispatch_site_counter++),
      &context.function);
  auto *switch_inst = switch_builder.CreateSwitch(
      dispatch_index, context.trap_block, context.instruction_blocks.size());

  llvm::SmallVector<llvm::BasicBlock *, 16> case_blocks;
  case_blocks.reserve(context.instruction_blocks.size());
  for (std::size_t instruction_index = 0;
       instruction_index < context.instruction_blocks.size(); ++instruction_index) {
    auto *case_block = llvm::BasicBlock::Create(
        context.function.getContext(),
        "dispatch.case.obf.vm." + std::to_string(context.dispatch_site_counter++) +
            "." + std::to_string(instruction_index),
        &context.function);
    switch_inst->addCase(
        switch_builder.getInt32(context.dispatch_index_for_instruction[instruction_index]),
        case_block);
    case_blocks.push_back(case_block);
  }

  llvm::IRBuilder<> emit_builder(emit_block);
  auto *dispatch_target = emit_builder.CreatePHI(
      llvm::PointerType::get(context.function.getContext(),
                             context.function.getAddressSpace()),
      context.instruction_blocks.size(), "obf.vm.dispatch.target");
  auto *dispatch =
      emit_builder.CreateIndirectBr(dispatch_target, context.instruction_blocks.size());
  for (llvm::BasicBlock *instruction_block : context.instruction_blocks) {
    dispatch->addDestination(instruction_block);
  }

  for (std::size_t instruction_index = 0;
       instruction_index < context.instruction_blocks.size(); ++instruction_index) {
    llvm::BasicBlock *instruction_block = context.instruction_blocks[instruction_index];
    llvm::IRBuilder<> case_builder(case_blocks[instruction_index]);
    llvm::Constant *plain_target = llvm::ConstantExpr::getPtrToInt(
        llvm::BlockAddress::get(&context.function, instruction_block),
        context.ptr_int_type);
    llvm::Value *is_match = case_builder.CreateICmpEQ(
        decoded_target, plain_target, "obf.vm.dispatch.match");
    case_builder.CreateCondBr(is_match, emit_block, context.trap_block);
    dispatch_target->addIncoming(llvm::BlockAddress::get(&context.function, instruction_block),
                                 case_blocks[instruction_index]);
  }
}

} // namespace obf::vm
