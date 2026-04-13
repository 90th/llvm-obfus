#include "obf/vm/virtualize.h"

#include "obf/transforms/mba.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Type.h"

#include <bit>
#include <algorithm>
#include <cstdint>
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

llvm::FastMathFlags decode_fast_math_flags(std::uint32_t flags) {
  llvm::FastMathFlags fast_math;
  fast_math.setAllowReassoc(
      has_instruction_flag(flags, instruction_flag_fast_reassoc));
  fast_math.setNoNaNs(has_instruction_flag(flags, instruction_flag_fast_nnan));
  fast_math.setNoInfs(has_instruction_flag(flags, instruction_flag_fast_ninf));
  fast_math.setNoSignedZeros(
      has_instruction_flag(flags, instruction_flag_fast_nsz));
  fast_math.setAllowReciprocal(
      has_instruction_flag(flags, instruction_flag_fast_arcp));
  fast_math.setAllowContract(
      has_instruction_flag(flags, instruction_flag_fast_contract));
  fast_math.setApproxFunc(has_instruction_flag(flags, instruction_flag_fast_afn));
  if (has_instruction_flag(flags, instruction_flag_fast_fast)) {
    fast_math.setFast();
  }
  return fast_math;
}

void apply_fast_math_flags(llvm::Instruction *instruction, std::uint32_t flags) {
  if (instruction == nullptr) {
    return;
  }

  instruction->setFastMathFlags(decode_fast_math_flags(flags));
}

using slot_cells = llvm::SmallVector<llvm::AllocaInst *, 4>;
using slot_storage = llvm::SmallVector<slot_cells, 16>;
using slot_cell_mapping = std::vector<std::uint32_t>;

inline constexpr std::uint32_t vm_slot_rotation_cell_count = 3;

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt);

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

llvm::Value *load_slot(llvm::IRBuilder<> &builder,
                       const slot_storage &slot_allocas,
                       llvm::ArrayRef<std::uint32_t> slot_mapping,
                       const bytecode_program &program, std::uint32_t slot) {
  const slot_desc &slot_info = program.slots[slot];
  return builder.CreateLoad(const_cast<llvm::Type *>(slot_info.type),
                            slot_allocas[slot][slot_mapping[slot]],
                            "obf.vm.slot");
}

void store_slot(llvm::IRBuilder<> &builder,
                const slot_storage &slot_allocas,
                llvm::ArrayRef<std::uint32_t> slot_mapping,
                std::uint32_t slot, llvm::Value *value) {
  builder.CreateStore(value, slot_allocas[slot][slot_mapping[slot]]);
}

void rotate_slot_cells(llvm::IRBuilder<> &builder, const slot_storage &slot_allocas,
                       const bytecode_program &program,
                       llvm::ArrayRef<std::uint32_t> current_mapping,
                       llvm::ArrayRef<std::uint32_t> target_mapping) {
  struct pending_slot_move {
    std::uint32_t slot = invalid_slot;
    llvm::Value *value = nullptr;
  };

  llvm::SmallVector<pending_slot_move, 16> pending_moves;
  pending_moves.reserve(program.slots.size());
  for (std::size_t slot_index = 0; slot_index < program.slots.size(); ++slot_index) {
    if (current_mapping[slot_index] == target_mapping[slot_index]) {
      continue;
    }

    const slot_desc &slot_info = program.slots[slot_index];
    pending_moves.push_back(
        {.slot = static_cast<std::uint32_t>(slot_index),
         .value = builder.CreateLoad(const_cast<llvm::Type *>(slot_info.type),
                                     slot_allocas[slot_index][current_mapping[slot_index]],
                                     "obf.vm.rot.load")});
  }

  for (const pending_slot_move &move : pending_moves) {
    builder.CreateStore(move.value,
                        slot_allocas[move.slot][target_mapping[move.slot]]);
    builder.CreateStore(
        llvm::Constant::getNullValue(
            const_cast<llvm::Type *>(program.slots[move.slot].type)),
        slot_allocas[move.slot][current_mapping[move.slot]]);
  }
}

bool should_obfuscate_vm_constant(const llvm::ConstantInt &constant) {
  if (constant.getType()->isIntegerTy(1)) {
    return false;
  }

  const llvm::APInt &value = constant.getValue();
  return !(value.isZero() || value.isOne() || value.isAllOnes());
}

std::uint64_t derive_vm_opaque_seed(const llvm::Function &function,
                                    const bytecode_program &program) {
  std::uint64_t seed =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName()));
  seed ^= static_cast<std::uint64_t>(program.instructions.size())
          * 0x9e3779b97f4a7c15ULL;
  seed ^= static_cast<std::uint64_t>(program.slots.size()) << 32;
  if (seed == 0) {
    seed = 0x6a09e667f3bcc909ULL;
  }

  return seed;
}

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_vm_bytecode_seed(const llvm::Function &function,
                                      const bytecode_program &program) {
  std::uint64_t seed = derive_vm_opaque_seed(function, program);
  seed = mix_seed(seed, 0x6eed0e9da4d94a4fULL);
  return seed == 0 ? 0x4f1bbcdc6762d5f1ULL : seed;
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
                                    name.empty() ? "obf.vm.token.seed"
                                                 : name);
  }

  return selected;
}

struct bytecode_layout {
  std::uint32_t header_offset = 0;
  std::uint32_t fallthrough_target_offset = invalid_slot;
  std::vector<std::uint32_t> edge_target_offsets;
  std::uint32_t integrity_probe_range = 0;
  std::uint64_t expected_post_header_state = 0;
};

struct serialized_bytecode_program {
  std::vector<std::uint8_t> bytes;
  std::vector<bytecode_layout> layouts;
};

std::uint32_t value_descriptor(const value_ref &value) {
  if (value.kind == value_ref_kind::slot) {
    return value.slot;
  }

  return static_cast<std::uint32_t>(llvm::hash_combine(value.constant,
                                                       value.constant->getType()));
}

std::uint8_t derive_bytecode_key(std::uint64_t state, std::uint32_t offset,
                                 std::uint64_t seed_base) {
  const std::uint64_t mixed =
      state ^ std::rotr(state, 13) ^ mix_seed(seed_base, offset + 1);
  return static_cast<std::uint8_t>(mixed & 0xffU);
}

std::uint64_t advance_bytecode_state(std::uint64_t state, std::uint8_t decoded) {
  return (state << 8) | static_cast<std::uint64_t>(decoded);
}

std::uint64_t integrity_fold_state(std::uint64_t state,
                                   std::uint8_t ciphertext_byte) {
  const std::uint64_t rotated = std::rotr(state, 7);
  const std::uint64_t scaled =
      static_cast<std::uint64_t>(ciphertext_byte) * 0x517cc1b727220a95ULL;
  return state ^ (rotated + scaled);
}

void append_encoded_u8(std::vector<std::uint8_t> &bytes, std::uint8_t decoded,
                       std::uint64_t &state, std::uint64_t seed_base) {
  const std::uint32_t offset = static_cast<std::uint32_t>(bytes.size());
  bytes.push_back(decoded ^ derive_bytecode_key(state, offset, seed_base));
  state = advance_bytecode_state(state, decoded);
}

void append_encoded_u32(std::vector<std::uint8_t> &bytes, std::uint32_t decoded,
                        std::uint64_t &state, std::uint64_t seed_base) {
  for (unsigned byte_index = 0; byte_index < 4; ++byte_index) {
    append_encoded_u8(bytes, static_cast<std::uint8_t>(decoded >> (byte_index * 8)),
                      state, seed_base);
  }
}

void append_rekey_state(std::vector<std::uint8_t> &bytes, std::uint64_t target_state,
                        std::uint64_t &state, std::uint64_t seed_base) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    append_encoded_u8(bytes, static_cast<std::uint8_t>(target_state >> shift), state,
                      seed_base);
  }
}

std::vector<std::uint32_t>
build_dispatch_index_map(const bytecode_program &program, std::uint64_t seed) {
  std::vector<std::uint32_t> order(program.instructions.size());
  std::iota(order.begin(), order.end(), 0U);
  std::stable_sort(order.begin(), order.end(), [&](std::uint32_t lhs,
                                                   std::uint32_t rhs) {
    const std::uint64_t lhs_key = mix_seed(seed, lhs + 1);
    const std::uint64_t rhs_key = mix_seed(seed, rhs + 1);
    return lhs_key == rhs_key ? lhs < rhs : lhs_key < rhs_key;
  });

  std::vector<std::uint32_t> dispatch_index_for_instruction(order.size(), 0);
  for (std::uint32_t dispatch_index = 0; dispatch_index < order.size();
       ++dispatch_index) {
    dispatch_index_for_instruction[order[dispatch_index]] = dispatch_index;
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

serialized_bytecode_program serialize_bytecode_program(
    const bytecode_program &program,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    llvm::ArrayRef<std::uint64_t> entry_states, std::uint64_t seed_base) {
  serialized_bytecode_program serialized;
  serialized.layouts.resize(program.instructions.size());

  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    bytecode_layout &layout = serialized.layouts[instruction_index];
    layout.header_offset = static_cast<std::uint32_t>(serialized.bytes.size());

    std::uint64_t header_state = entry_states[instruction_index];
    append_encoded_u8(serialized.bytes,
                      static_cast<std::uint8_t>(instruction.op), header_state,
                      seed_base);
    append_encoded_u32(serialized.bytes, instruction.subtype, header_state,
                       seed_base);
    append_encoded_u32(serialized.bytes, instruction.flags, header_state,
                       seed_base);
    append_encoded_u32(serialized.bytes, instruction.immediate, header_state,
                       seed_base);
    append_encoded_u32(serialized.bytes, instruction.result_slot, header_state,
                       seed_base);
    append_encoded_u8(serialized.bytes,
                      static_cast<std::uint8_t>(instruction.operands.size()),
                      header_state, seed_base);
    for (const value_ref &operand : instruction.operands) {
      append_encoded_u8(serialized.bytes,
                        static_cast<std::uint8_t>(operand.kind), header_state,
                        seed_base);
      append_encoded_u32(serialized.bytes, value_descriptor(operand), header_state,
                         seed_base);
    }
    append_encoded_u8(serialized.bytes,
                      static_cast<std::uint8_t>(instruction.edges.size()),
                      header_state, seed_base);

    layout.integrity_probe_range =
        static_cast<std::uint32_t>(serialized.bytes.size());
    if (layout.integrity_probe_range > 0) {
      const std::uint32_t num_probes = 2U + static_cast<std::uint32_t>(
          mix_seed(seed_base, 0xfade0000ULL + instruction_index) % 3);
      for (std::uint32_t probe = 0; probe < num_probes; ++probe) {
        const std::uint32_t probe_offset = static_cast<std::uint32_t>(
            mix_seed(seed_base,
                     static_cast<std::uint64_t>(instruction_index) * 0x1337ULL +
                         probe + 1) %
            layout.integrity_probe_range);
        header_state =
            integrity_fold_state(header_state, serialized.bytes[probe_offset]);
      }
    }

    layout.expected_post_header_state = header_state;

    const auto append_target_segment = [&](std::uint32_t target_instruction) {
      std::uint64_t segment_state = header_state;
      const std::uint32_t offset =
          static_cast<std::uint32_t>(serialized.bytes.size());
      append_encoded_u32(serialized.bytes,
                         dispatch_index_for_instruction[target_instruction],
                         segment_state, seed_base);
      append_rekey_state(serialized.bytes, entry_states[target_instruction],
                         segment_state, seed_base);
      return offset;
    };

    switch (instruction.op) {
    case opcode::jump:
    case opcode::branch:
    case opcode::switch_op:
      for (const control_edge &edge : instruction.edges) {
        layout.edge_target_offsets.push_back(append_target_segment(
            program.blocks[edge.target_block].first_instruction));
      }
      break;
    case opcode::ret:
    case opcode::unreachable_op:
      break;
    default:
      layout.fallthrough_target_offset =
          append_target_segment(static_cast<std::uint32_t>(instruction_index + 1));
      break;
    }
  }

  return serialized;
}

llvm::Value *build_opaque_vm_mask(llvm::IRBuilder<> &builder,
                                  llvm::AllocaInst *,
                                  std::uint64_t opaque_seed_base,
                                  llvm::IntegerType *type,
                                  const llvm::APInt &key,
                                  const mba::builder_context &mba_context,
                                  std::uint64_t salt) {
  const llvm::APInt base_seed(type->getBitWidth(), opaque_seed_base,
                              /*isSigned=*/false, /*implicitTrunc=*/true);
  mba::builder_context seed_context = mba_context;
  seed_context.seed_base = opaque_seed_base;
  llvm::Value *typed_seed = mba::create_opaque_integer(
      builder, type, seed_context, base_seed, salt ^ 0x51f15eedULL,
      "obf.vm.seed");
  const llvm::APInt delta = key ^ base_seed;
  return mba::create_xor(builder, typed_seed,
                         llvm::ConstantInt::get(type, delta), mba_context, salt,
                         "obf.vm.const.mask");
}

llvm::Value *materialize_constant(llvm::IRBuilder<> &builder,
                                  const llvm::Constant &constant,
                                  llvm::AllocaInst *opaque_seed_slot,
                                  std::uint64_t opaque_seed_base,
                                  const mba::builder_context &mba_context,
                                  std::uint64_t salt) {
  if (const auto *integer = llvm::dyn_cast<llvm::ConstantInt>(&constant)) {
    if (!should_obfuscate_vm_constant(*integer)) {
      return const_cast<llvm::ConstantInt *>(integer);
    }

    const llvm::APInt &value = integer->getValue();
    const std::uint64_t constant_salt =
        static_cast<std::uint64_t>(value.getBitWidth()) * 131ULL;
    const std::uint64_t word = value.getLimitedValue();
    const llvm::APInt key(value.getBitWidth(),
                          (word ^ 0x9e3779b97f4a7c15ULL) + constant_salt,
                          /*isSigned=*/false, /*implicitTrunc=*/true);
    const llvm::APInt encoded = value ^ key;
    llvm::Value *mask = build_opaque_vm_mask(
        builder, opaque_seed_slot, opaque_seed_base,
        llvm::cast<llvm::IntegerType>(integer->getType()), key, mba_context,
        salt ^ constant_salt ^ 0x13579bdfULL);
    return mba::create_xor(builder,
                           llvm::ConstantInt::get(integer->getType(), encoded),
                           mask, mba_context, salt ^ constant_salt ^ 0x2468ace0ULL,
                           "obf.vm.const");
  }

  return const_cast<llvm::Constant *>(&constant);
}

llvm::Value *materialize_value(llvm::IRBuilder<> &builder,
                               const slot_storage &slot_allocas,
                               llvm::ArrayRef<std::uint32_t> slot_mapping,
                               const bytecode_program &program,
                               const value_ref &value,
                               llvm::AllocaInst *opaque_seed_slot,
                               std::uint64_t opaque_seed_base,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  if (value.kind == value_ref_kind::slot) {
    return load_slot(builder, slot_allocas, slot_mapping, program, value.slot);
  }

  return materialize_constant(builder, *value.constant, opaque_seed_slot,
                              opaque_seed_base, mba_context, salt);
}

llvm::Value *emit_binary(llvm::IRBuilder<> &builder,
                         const slot_storage &slot_allocas,
                         llvm::ArrayRef<std::uint32_t> slot_mapping,
                         const bytecode_program &program,
                         const micro_instruction &instruction,
                         llvm::AllocaInst *opaque_seed_slot,
                         std::uint64_t opaque_seed_base,
                         const mba::builder_context &mba_context,
                         std::uint64_t salt) {
  llvm::Value *const lhs =
      materialize_value(builder, slot_allocas, slot_mapping, program,
                        instruction.operands[0],
                        opaque_seed_slot, opaque_seed_base, mba_context,
                        salt + 1);
  llvm::Value *const rhs =
      materialize_value(builder, slot_allocas, slot_mapping, program,
                        instruction.operands[1],
                        opaque_seed_slot, opaque_seed_base, mba_context,
                        salt + 2);

  llvm::Value *result = nullptr;
  const auto subopcode = static_cast<binary_opcode>(instruction.subtype);
  switch (subopcode) {
  case binary_opcode::add:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_add(builder, lhs, rhs, mba_context, salt + 3,
                               "obf.vm.add");
    } else {
      result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    }
    break;
  case binary_opcode::sub:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_sub(builder, lhs, rhs, mba_context, salt + 4,
                               "obf.vm.sub");
    } else {
      result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    }
    break;
  case binary_opcode::mul:
    result = builder.CreateMul(lhs, rhs, "obf.vm.mul");
    break;
  case binary_opcode::udiv:
    result = builder.CreateUDiv(lhs, rhs, "obf.vm.udiv");
    break;
  case binary_opcode::sdiv:
    result = builder.CreateSDiv(lhs, rhs, "obf.vm.sdiv");
    break;
  case binary_opcode::urem:
    result = builder.CreateURem(lhs, rhs, "obf.vm.urem");
    break;
  case binary_opcode::srem:
    result = builder.CreateSRem(lhs, rhs, "obf.vm.srem");
    break;
  case binary_opcode::shl:
    result = builder.CreateShl(lhs, rhs, "obf.vm.shl");
    break;
  case binary_opcode::lshr:
    result = builder.CreateLShr(lhs, rhs, "obf.vm.lshr");
    break;
  case binary_opcode::ashr:
    result = builder.CreateAShr(lhs, rhs, "obf.vm.ashr");
    break;
  case binary_opcode::and_op:
    result = builder.CreateAnd(lhs, rhs, "obf.vm.and");
    break;
  case binary_opcode::or_op:
    result = builder.CreateOr(lhs, rhs, "obf.vm.or");
    break;
  case binary_opcode::xor_op:
    result = mba::create_xor(builder, lhs, rhs, mba_context, salt + 5,
                             "obf.vm.xor");
    break;
  case binary_opcode::fadd:
    result = builder.CreateFAdd(lhs, rhs, "obf.vm.fadd");
    break;
  case binary_opcode::fsub:
    result = builder.CreateFSub(lhs, rhs, "obf.vm.fsub");
    break;
  case binary_opcode::fmul:
    result = builder.CreateFMul(lhs, rhs, "obf.vm.fmul");
    break;
  case binary_opcode::fdiv:
    result = builder.CreateFDiv(lhs, rhs, "obf.vm.fdiv");
    break;
  case binary_opcode::frem:
    result = builder.CreateFRem(lhs, rhs, "obf.vm.frem");
    break;
  }

  auto *binary = llvm::cast<llvm::BinaryOperator>(result);
  if (has_instruction_flag(instruction.flags, instruction_flag_nsw)) {
    binary->setHasNoSignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
    binary->setHasNoUnsignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_exact)) {
    switch (subopcode) {
    case binary_opcode::udiv:
    case binary_opcode::sdiv:
    case binary_opcode::lshr:
    case binary_opcode::ashr:
      binary->setIsExact();
      break;
    default:
      break;
    }
  }
  apply_fast_math_flags(binary, instruction.flags);
  return result;
}

llvm::Value *emit_cast(llvm::IRBuilder<> &builder,
                       const slot_storage &slot_allocas,
                       llvm::ArrayRef<std::uint32_t> slot_mapping,
                       const bytecode_program &program,
                       const micro_instruction &instruction,
                       llvm::AllocaInst *opaque_seed_slot,
                       std::uint64_t opaque_seed_base,
                       const mba::builder_context &mba_context,
                       std::uint64_t salt) {
  llvm::Value *const operand =
      materialize_value(builder, slot_allocas, slot_mapping, program,
                        instruction.operands[0],
                        opaque_seed_slot, opaque_seed_base, mba_context,
                        salt + 1);
  llvm::Type *const destination_type =
      const_cast<llvm::Type *>(program.slots[instruction.result_slot].type);

  switch (static_cast<cast_opcode>(instruction.subtype)) {
  case cast_opcode::trunc:
    return builder.CreateTrunc(operand, destination_type, "obf.vm.trunc");
  case cast_opcode::zext:
    return builder.CreateZExt(operand, destination_type, "obf.vm.zext");
  case cast_opcode::sext:
    return builder.CreateSExt(operand, destination_type, "obf.vm.sext");
  case cast_opcode::fp_trunc:
    return builder.CreateFPTrunc(operand, destination_type, "obf.vm.fptrunc");
  case cast_opcode::fp_ext:
    return builder.CreateFPExt(operand, destination_type, "obf.vm.fpext");
  case cast_opcode::ui_to_fp:
    return builder.CreateUIToFP(operand, destination_type, "obf.vm.uitofp");
  case cast_opcode::si_to_fp:
    return builder.CreateSIToFP(operand, destination_type, "obf.vm.sitofp");
  case cast_opcode::fp_to_ui:
    return builder.CreateFPToUI(operand, destination_type, "obf.vm.fptoui");
  case cast_opcode::fp_to_si:
    return builder.CreateFPToSI(operand, destination_type, "obf.vm.fptosi");
  case cast_opcode::ptr_to_int:
    return builder.CreatePtrToInt(operand, destination_type, "obf.vm.ptrtoint");
  case cast_opcode::int_to_ptr:
    return builder.CreateIntToPtr(operand, destination_type, "obf.vm.inttoptr");
  case cast_opcode::bitcast:
    return builder.CreateBitCast(operand, destination_type, "obf.vm.bitcast");
  case cast_opcode::addrspace_cast:
    return builder.CreateAddrSpaceCast(operand, destination_type,
                                       "obf.vm.addrspacecast");
  }

  return nullptr;
}

void apply_edge_assignments(
    llvm::IRBuilder<> &builder,
    const slot_storage &slot_allocas,
    llvm::ArrayRef<std::uint32_t> slot_mapping,
    const bytecode_program &program, const control_edge &edge,
    llvm::AllocaInst *opaque_seed_slot, std::uint64_t opaque_seed_base,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  llvm::SmallVector<llvm::Value *, 8> incoming_values;
  incoming_values.reserve(edge.assignments.size());
  for (const edge_assignment &assignment : edge.assignments) {
    incoming_values.push_back(
        materialize_value(builder, slot_allocas, slot_mapping, program,
                          assignment.value,
                          opaque_seed_slot, opaque_seed_base, mba_context,
                          salt + incoming_values.size() + 1));
  }

  for (std::size_t assignment_index = 0;
       assignment_index < edge.assignments.size(); ++assignment_index) {
    store_slot(builder, slot_allocas, slot_mapping,
               edge.assignments[assignment_index].slot,
               incoming_values[assignment_index]);
  }
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

  const std::uint64_t opaque_seed_base =
      derive_vm_opaque_seed(function, program);
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

  const std::uint64_t bytecode_seed =
      derive_vm_bytecode_seed(function, program);
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed);

  llvm::GlobalVariable *bytecode_global = nullptr;
  if (!serialized.bytes.empty()) {
    auto *bytecode_type = llvm::ArrayType::get(entry_builder.getInt8Ty(),
                                               serialized.bytes.size());
    bytecode_global = new llvm::GlobalVariable(
        *function.getParent(), bytecode_type, true,
        llvm::GlobalValue::PrivateLinkage,
        llvm::ConstantDataArray::get(context, serialized.bytes),
        "__obf_vm_bc_" + symbol_tag);
    bytecode_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  }

  // Create return-key global for integer-returning functions.
  // The caller-side rewriter looks this up by name to decode return values.
  llvm::GlobalVariable *retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value =
        derive_vm_return_key(function, program);
    retkey_global = new llvm::GlobalVariable(
        *function.getParent(), entry_builder.getInt64Ty(),
        /*isConstant=*/false, llvm::GlobalValue::PrivateLinkage,
        entry_builder.getInt64(retkey_value),
        "__obf_vm_retkey_" + symbol_tag);
  }

  auto *state_slot = entry_builder.CreateAlloca(entry_builder.getInt64Ty(), nullptr,
                                                "obf.vm.state");

  const std::uint32_t entry_instruction =
      program.blocks.empty() ? 0 : program.blocks.front().first_instruction;
  const slot_cell_mapping entry_identity_mapping(program.slots.size(), 0);
  llvm::ArrayRef<std::uint32_t> entry_slot_mapping = entry_identity_mapping;
  if (!slot_mappings.empty()) {
    entry_slot_mapping = slot_mappings[entry_instruction];
  }
  auto *state_store = entry_builder.CreateStore(
      build_hidden_token_seed(
          entry_builder, hidden_token_arg,
          program.instructions.empty() ? bytecode_seed
                                       : entry_states[entry_instruction],
          options.valid_hidden_tokens, mba_context, 0x3100,
          "obf.vm.token.state"),
      state_slot);
  (void)state_store;

  llvm::AllocaInst *dispatch_table = nullptr;
  llvm::ArrayType *dispatch_table_type = nullptr;
  llvm::IntegerType *ptr_int_type = nullptr;
  if (!instruction_blocks.empty()) {
    const llvm::DataLayout &data_layout = function.getParent()->getDataLayout();
    ptr_int_type =
        data_layout.getIntPtrType(context, function.getAddressSpace());
    dispatch_table_type =
        llvm::ArrayType::get(ptr_int_type, instruction_blocks.size());
    dispatch_table = entry_builder.CreateAlloca(dispatch_table_type, nullptr,
                                                "obf.vm.dispatch.table");
  }

  std::size_t argument_index = 0;
  for (llvm::Argument &argument : function.args()) {
    store_slot(entry_builder, slot_allocas, entry_slot_mapping,
               program.argument_slots[argument_index++], &argument);
  }

  std::uint64_t dispatch_site_counter = 0;
  const auto build_dispatch_key = [&](llvm::IRBuilder<> &builder,
                                      llvm::Value *dispatch_index,
                                      std::uint64_t salt) {
    llvm::Value *typed_seed = nullptr;
    if (hidden_token_arg != nullptr) {
      typed_seed = hidden_token_arg;
      if (typed_seed->getType() != ptr_int_type) {
        typed_seed = builder.CreateZExtOrTrunc(typed_seed, ptr_int_type,
                                               "obf.vm.dispatch.seed.cast");
      }
      typed_seed = mba::entangle_value(builder, typed_seed, mba_context,
                                       salt ^ 0x7000ULL,
                                       "obf.vm.dispatch.seed");
    } else {
      typed_seed = mba::create_opaque_integer(
          builder, ptr_int_type, mba_context,
          llvm::APInt(ptr_int_type->getBitWidth(), opaque_seed_base,
                      /*isSigned=*/false, /*implicitTrunc=*/true),
          salt ^ 0x7000ULL, "obf.vm.dispatch.seed");
    }

    llvm::Value *typed_index = dispatch_index;
    if (typed_index->getType() != ptr_int_type) {
      typed_index = builder.CreateZExt(typed_index, ptr_int_type,
                                       "obf.vm.dispatch.index.cast");
    }

    llvm::Value *seed_mix = mba::create_xor(
        builder, typed_seed,
        llvm::ConstantInt::get(ptr_int_type,
                              mix_seed(bytecode_seed, 0x7001ULL)),
        mba_context, salt + 1, "obf.vm.dispatch.seed.mix");
    llvm::Value *index_mix = mba::create_add(
        builder, typed_index,
        llvm::ConstantInt::get(ptr_int_type,
                              mix_seed(bytecode_seed, 0x7002ULL)),
        mba_context, salt + 2, "obf.vm.dispatch.index.mix");
    return mba::create_xor(builder, seed_mix, index_mix, mba_context, salt + 3,
                           "obf.vm.dispatch.key");
  };

  if (!instruction_blocks.empty()) {
    for (std::size_t instruction_index = 0;
         instruction_index < instruction_blocks.size(); ++instruction_index) {
      const std::uint32_t dispatch_index =
          dispatch_index_for_instruction[instruction_index];
      llvm::Value *slot = entry_builder.CreateInBoundsGEP(
          dispatch_table_type, dispatch_table,
          {entry_builder.getInt32(0), entry_builder.getInt32(dispatch_index)},
          "obf.vm.dispatch.slot." + std::to_string(dispatch_index));
      llvm::Value *plain_target = entry_builder.CreatePtrToInt(
          llvm::BlockAddress::get(&function, instruction_blocks[instruction_index]),
          ptr_int_type, "obf.vm.dispatch.addr." + std::to_string(dispatch_index));
      llvm::Value *key = build_dispatch_key(entry_builder,
                                            entry_builder.getInt32(dispatch_index),
                                            0x4000 + dispatch_index);
      llvm::Value *encoded_target = mba::create_xor(
          entry_builder, plain_target, key, mba_context, 0x5000 + dispatch_index,
          "obf.vm.dispatch.enc." + std::to_string(dispatch_index));
      entry_builder.CreateStore(encoded_target, slot);
    }
  }

  const auto fetch_byte = [&](llvm::IRBuilder<> &builder, std::uint32_t offset,
                              std::uint64_t salt) -> llvm::Value * {
    llvm::Value *slot = builder.CreateInBoundsGEP(
        bytecode_global->getValueType(), bytecode_global,
        {builder.getInt32(0), builder.getInt32(offset)}, "obf.vm.bc.slot");
    llvm::Value *encoded =
        builder.CreateLoad(builder.getInt8Ty(), slot, "obf.vm.bc.enc");
    auto *state_load = builder.CreateLoad(builder.getInt64Ty(), state_slot,
                                          "obf.vm.bc.state.load");
    llvm::Value *rotated = builder.CreateOr(
        builder.CreateLShr(state_load, builder.getInt64(13), "obf.vm.bc.shr"),
        builder.CreateShl(state_load, builder.getInt64(51), "obf.vm.bc.shl"),
        "obf.vm.bc.rot");
    llvm::Value *key_mix = mba::create_xor(builder, state_load, rotated,
                                           mba_context, salt + 1,
                                           "obf.vm.bc.key.mix");
    llvm::Value *key_word = mba::create_xor(
        builder, key_mix,
        builder.getInt64(mix_seed(bytecode_seed, static_cast<std::uint64_t>(offset) + 1)),
        mba_context, salt + 2, "obf.vm.bc.key.word");
    llvm::Value *key =
        builder.CreateTrunc(key_word, builder.getInt8Ty(), "obf.vm.bc.key");
    llvm::Value *decoded = mba::create_xor(builder, encoded, key, mba_context,
                                           salt + 3, "obf.vm.bc.byte");
    llvm::Value *next_state = builder.CreateOr(
        builder.CreateShl(state_load, builder.getInt64(8), "obf.vm.bc.state.shift"),
        builder.CreateZExt(decoded, builder.getInt64Ty(), "obf.vm.bc.state.byte"),
        "obf.vm.bc.state.next");
    (void)builder.CreateStore(next_state, state_slot);
    return decoded;
  };

  const auto fetch_u32 = [&](llvm::IRBuilder<> &builder, std::uint32_t offset,
                             std::uint64_t salt) -> llvm::Value * {
    llvm::Value *word = builder.CreateZExt(fetch_byte(builder, offset, salt),
                                           builder.getInt32Ty(),
                                           "obf.vm.bc.word.0");
    for (unsigned byte_index = 1; byte_index < 4; ++byte_index) {
      llvm::Value *piece = builder.CreateShl(
          builder.CreateZExt(fetch_byte(builder, offset + byte_index,
                                        salt + byte_index),
                             builder.getInt32Ty(), "obf.vm.bc.word.byte"),
          builder.getInt32(byte_index * 8), "obf.vm.bc.word.shl");
      word = builder.CreateOr(word, piece, "obf.vm.bc.word");
    }
    return word;
  };

  const auto consume_metadata = [&](llvm::IRBuilder<> &builder,
                                    const micro_instruction &instruction,
                                    const bytecode_layout &layout,
                                    std::uint64_t salt) {
    std::uint32_t cursor = layout.header_offset;
    std::uint64_t local_salt = salt;
    (void)fetch_byte(builder, cursor++, local_salt++);
    (void)fetch_u32(builder, cursor, local_salt);
    cursor += 4;
    local_salt += 4;
    (void)fetch_u32(builder, cursor, local_salt);
    cursor += 4;
    local_salt += 4;
    (void)fetch_u32(builder, cursor, local_salt);
    cursor += 4;
    local_salt += 4;
    (void)fetch_u32(builder, cursor, local_salt);
    cursor += 4;
    local_salt += 4;
    (void)fetch_byte(builder, cursor++, local_salt++);
    for (std::size_t operand_index = 0; operand_index < instruction.operands.size();
         ++operand_index) {
      (void)fetch_byte(builder, cursor++, local_salt++);
      (void)fetch_u32(builder, cursor, local_salt);
      cursor += 4;
      local_salt += 4;
    }
    (void)fetch_byte(builder, cursor, local_salt);
  };

  const auto decode_target_dispatch = [&](llvm::IRBuilder<> &builder,
                                          std::uint32_t offset,
                                          std::uint64_t salt) {
    llvm::Value *target = fetch_u32(builder, offset, salt);
    for (unsigned byte_index = 0; byte_index < 8; ++byte_index) {
      (void)fetch_byte(builder, offset + 4 + byte_index, salt + 4 + byte_index);
    }
    return target;
  };

  const auto emit_dispatch = [&](llvm::IRBuilder<> &builder,
                                 llvm::Value *dispatch_index,
                                 std::uint64_t salt) {
    auto *jump_block = llvm::BasicBlock::Create(
        context, "dispatch.jump.obf.vm." + std::to_string(dispatch_site_counter++),
        &function);
    llvm::Value *in_range = builder.CreateICmpULT(
        dispatch_index,
        builder.getInt32(static_cast<std::uint32_t>(instruction_blocks.size())),
        "obf.vm.dispatch.inrange");
    builder.CreateCondBr(in_range, jump_block, trap_block);

    llvm::IRBuilder<> jump_builder(jump_block);
    llvm::Value *dispatch_slot = jump_builder.CreateInBoundsGEP(
        dispatch_table_type, dispatch_table,
        {jump_builder.getInt32(0), dispatch_index}, "obf.vm.dispatch.slot");
    auto *encoded_target = jump_builder.CreateLoad(ptr_int_type, dispatch_slot,
                                                   "obf.vm.dispatch.encoded");
    llvm::Value *key = build_dispatch_key(jump_builder, dispatch_index, salt);
    llvm::Value *decoded_target = mba::create_xor(
        jump_builder, encoded_target, key, mba_context, salt + 1,
        "obf.vm.dispatch.target.int");

    llvm::Value *dispatch_target = nullptr;
    llvm::Value *target_match = nullptr;
    for (llvm::BasicBlock *instruction_block : instruction_blocks) {
      llvm::Constant *plain_target = llvm::ConstantExpr::getPtrToInt(
          llvm::BlockAddress::get(&function, instruction_block), ptr_int_type);
      llvm::Value *is_match = jump_builder.CreateICmpEQ(
          decoded_target, plain_target, "obf.vm.dispatch.match");
      if (dispatch_target == nullptr) {
        dispatch_target = llvm::BlockAddress::get(&function, instruction_block);
        target_match = is_match;
        continue;
      }

      target_match =
          jump_builder.CreateOr(target_match, is_match, "obf.vm.dispatch.any");
      dispatch_target = jump_builder.CreateSelect(
          is_match, llvm::BlockAddress::get(&function, instruction_block),
          dispatch_target, "obf.vm.dispatch.target");
    }

    auto *emit_block = llvm::BasicBlock::Create(
        context, "dispatch.emit.obf.vm." + std::to_string(dispatch_site_counter++),
        &function);
    jump_builder.CreateCondBr(target_match, emit_block, trap_block);

    llvm::IRBuilder<> emit_builder(emit_block);
    auto *dispatch =
        emit_builder.CreateIndirectBr(dispatch_target, instruction_blocks.size());
    for (llvm::BasicBlock *instruction_block : instruction_blocks) {
      dispatch->addDestination(instruction_block);
    }
  };

  if (instruction_blocks.empty()) {
    entry_builder.CreateBr(trap_block);
  } else {
    emit_dispatch(entry_builder,
                  entry_builder.getInt32(dispatch_index_for_instruction[entry_instruction]),
                  0x3000);
  }

  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    llvm::IRBuilder<> builder(instruction_blocks[instruction_index]);
    const bytecode_layout &layout = serialized.layouts[instruction_index];
    const llvm::ArrayRef<std::uint32_t> current_slot_mapping(
        slot_mappings[instruction_index]);
    consume_metadata(builder, instruction, layout,
                     0x8000 + static_cast<std::uint64_t>(instruction_index) * 32);

    if (layout.integrity_probe_range > 0 && bytecode_global != nullptr) {
      const std::uint32_t num_probes = 2U + static_cast<std::uint32_t>(
          mix_seed(bytecode_seed, 0xfade0000ULL + instruction_index) % 3);
      for (std::uint32_t probe = 0; probe < num_probes; ++probe) {
        const std::uint32_t probe_offset = static_cast<std::uint32_t>(
            mix_seed(bytecode_seed,
                     static_cast<std::uint64_t>(instruction_index) * 0x1337ULL +
                         probe + 1) %
            layout.integrity_probe_range);
        llvm::Value *byte_ptr = builder.CreateInBoundsGEP(
            bytecode_global->getValueType(), bytecode_global,
            {builder.getInt32(0), builder.getInt32(probe_offset)},
            "obf.vm.integrity.ptr");
        llvm::Value *cipher_byte = builder.CreateLoad(
            builder.getInt8Ty(), byte_ptr, "obf.vm.integrity.byte");
        auto *integrity_state = builder.CreateLoad(builder.getInt64Ty(),
                                                   state_slot,
                                                   "obf.vm.integrity.state");
        llvm::Value *rotated = builder.CreateOr(
            builder.CreateLShr(integrity_state, builder.getInt64(7),
                               "obf.vm.integrity.shr"),
            builder.CreateShl(integrity_state, builder.getInt64(57),
                              "obf.vm.integrity.shl"),
            "obf.vm.integrity.rot");
        llvm::Value *extended = builder.CreateZExt(
            cipher_byte, builder.getInt64Ty(), "obf.vm.integrity.ext");
        llvm::Value *scaled = builder.CreateMul(
            extended, builder.getInt64(0x517cc1b727220a95ULL),
            "obf.vm.integrity.scale");
        llvm::Value *folded = builder.CreateXor(
            integrity_state,
            builder.CreateAdd(rotated, scaled, "obf.vm.integrity.sum"),
            "obf.vm.integrity.fold");
        (void)builder.CreateStore(folded, state_slot);
      }
    }

    const auto rotate_to_mapping = [&](llvm::IRBuilder<> &rotation_builder,
                                       std::uint32_t target_instruction) {
      if (target_instruction >= slot_mappings.size()) {
        return;
      }

      rotate_slot_cells(rotation_builder, slot_allocas, program,
                        current_slot_mapping,
                        llvm::ArrayRef<std::uint32_t>(slot_mappings[target_instruction]));
    };

    const auto finish_value = [&](llvm::Value *result) {
      if (instruction.result_slot != invalid_slot) {
        store_slot(builder, slot_allocas, current_slot_mapping,
                   instruction.result_slot, result);
      }
      if (instruction_index + 1 < slot_mappings.size()) {
        rotate_to_mapping(builder,
                          static_cast<std::uint32_t>(instruction_index + 1));
      }
      llvm::Value *next_target = decode_target_dispatch(
          builder, layout.fallthrough_target_offset,
          0x9000 + static_cast<std::uint64_t>(instruction_index) * 32);
      emit_dispatch(builder, next_target,
                    0xa000 + static_cast<std::uint64_t>(instruction_index) * 32);
    };

    switch (instruction.op) {
    case opcode::binary:
      finish_value(emit_binary(builder, slot_allocas, current_slot_mapping,
                               program, instruction, opaque_seed,
                               opaque_seed_base, mba_context,
                               0xb000 + static_cast<std::uint64_t>(instruction_index)));
      break;
    case opcode::cast:
      finish_value(emit_cast(builder, slot_allocas, current_slot_mapping,
                             program, instruction, opaque_seed,
                             opaque_seed_base, mba_context,
                             0xc000 + static_cast<std::uint64_t>(instruction_index)));
      break;
    case opcode::freeze:
      finish_value(builder.CreateFreeze(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xd000 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.freeze"));
      break;
    case opcode::icmp:
      finish_value(builder.CreateICmp(
          static_cast<llvm::CmpInst::Predicate>(instruction.subtype),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xe000 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xe100 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.icmp"));
      break;
    case opcode::fcmp: {
      auto *compare = llvm::cast<llvm::Instruction>(builder.CreateFCmp(
          static_cast<llvm::CmpInst::Predicate>(instruction.subtype),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xf000 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xf100 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.fcmp"));
      apply_fast_math_flags(compare, instruction.flags);
      finish_value(compare);
      break;
    }
    case opcode::select:
      finish_value(builder.CreateSelect(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x10000 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x10100 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[2], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x10200 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.select"));
      break;
    case opcode::load: {
      auto *load = builder.CreateLoad(
          const_cast<llvm::Type *>(instruction.type),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x11000 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.load");
      if (instruction.immediate != 0) {
        load->setAlignment(llvm::Align(instruction.immediate));
      }
      finish_value(load);
      break;
    }
    case opcode::store: {
      auto *store = builder.CreateStore(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12000 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12100 + static_cast<std::uint64_t>(instruction_index)));
      if (instruction.immediate != 0) {
        store->setAlignment(llvm::Align(instruction.immediate));
      }
      if (instruction_index + 1 < slot_mappings.size()) {
        rotate_to_mapping(builder,
                          static_cast<std::uint32_t>(instruction_index + 1));
      }
      llvm::Value *next_target = decode_target_dispatch(
          builder, layout.fallthrough_target_offset,
          0x12200 + static_cast<std::uint64_t>(instruction_index));
      emit_dispatch(builder, next_target,
                    0x12300 + static_cast<std::uint64_t>(instruction_index));
      break;
    }
    case opcode::gep: {
      llvm::SmallVector<llvm::Value *, 4> indices;
      indices.reserve(instruction.operands.size() - 1);
      for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
           ++operand_index) {
        indices.push_back(materialize_value(builder, slot_allocas,
                                            current_slot_mapping, program,
                                            instruction.operands[operand_index],
                                            opaque_seed, opaque_seed_base,
                                            mba_context,
                                            0x13000 +
                                                static_cast<std::uint64_t>(instruction_index) *
                                                    16 +
                                                operand_index));
      }

      llvm::Value *gep = nullptr;
      llvm::Value *const pointer =
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x13100 + static_cast<std::uint64_t>(instruction_index));
      if (has_instruction_flag(instruction.flags, instruction_flag_inbounds)) {
        gep = builder.CreateInBoundsGEP(const_cast<llvm::Type *>(instruction.type),
                                        pointer, indices, "obf.vm.gep");
      } else {
        gep = builder.CreateGEP(const_cast<llvm::Type *>(instruction.type), pointer,
                                indices, "obf.vm.gep");
      }
      finish_value(gep);
      break;
    }
    case opcode::call: {
      llvm::SmallVector<llvm::Value *, 8> arguments;
      arguments.reserve(instruction.operands.size() - 1);
      for (std::size_t operand_index = 1; operand_index < instruction.operands.size();
           ++operand_index) {
        arguments.push_back(materialize_value(builder, slot_allocas,
                                              current_slot_mapping, program,
                                              instruction.operands[operand_index],
                                              opaque_seed, opaque_seed_base,
                                              mba_context,
                                              0x14000 +
                                                  static_cast<std::uint64_t>(instruction_index) *
                                                      16 +
                                                  operand_index));
      }

      auto *call = builder.CreateCall(
          llvm::cast<llvm::FunctionType>(const_cast<llvm::Type *>(instruction.type)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x14100 + static_cast<std::uint64_t>(instruction_index)),
          arguments,
          instruction.result_slot == invalid_slot ? "" : "obf.vm.call");
      call->setCallingConv(
          static_cast<llvm::CallingConv::ID>(instruction.subtype));
      call->setAttributes(instruction.attributes);
      apply_fast_math_flags(call, instruction.flags);
      if (instruction.result_slot != invalid_slot) {
        store_slot(builder, slot_allocas, current_slot_mapping,
                   instruction.result_slot, call);
      }
      if (instruction_index + 1 < slot_mappings.size()) {
        rotate_to_mapping(builder,
                          static_cast<std::uint32_t>(instruction_index + 1));
      }
      llvm::Value *next_target = decode_target_dispatch(
          builder, layout.fallthrough_target_offset,
          0x14200 + static_cast<std::uint64_t>(instruction_index));
      emit_dispatch(builder, next_target,
                    0x14300 + static_cast<std::uint64_t>(instruction_index));
      break;
    }
    case opcode::jump:
      apply_edge_assignments(builder, slot_allocas, current_slot_mapping, program,
                             instruction.edges[0], opaque_seed,
                             opaque_seed_base, mba_context,
                             0x15000 + static_cast<std::uint64_t>(instruction_index));
      rotate_to_mapping(builder,
                        program.blocks[instruction.edges[0].target_block]
                            .first_instruction);
      emit_dispatch(builder,
                    decode_target_dispatch(
                        builder, layout.edge_target_offsets[0],
                        0x15100 + static_cast<std::uint64_t>(instruction_index)),
                    0x15200 + static_cast<std::uint64_t>(instruction_index));
      break;
    case opcode::branch: {
      auto *true_block = llvm::BasicBlock::Create(
          context, "vm.edge.true." + std::to_string(instruction_index), &function);
      auto *false_block = llvm::BasicBlock::Create(
          context, "vm.edge.false." + std::to_string(instruction_index), &function);
      builder.CreateCondBr(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x16000 + static_cast<std::uint64_t>(instruction_index)),
          true_block, false_block);

      llvm::IRBuilder<> true_builder(true_block);
      apply_edge_assignments(true_builder, slot_allocas, current_slot_mapping,
                             program, instruction.edges[0], opaque_seed,
                             opaque_seed_base, mba_context,
                             0x16100 + static_cast<std::uint64_t>(instruction_index));
      rotate_to_mapping(true_builder,
                        program.blocks[instruction.edges[0].target_block]
                            .first_instruction);
      emit_dispatch(true_builder,
                    decode_target_dispatch(
                        true_builder, layout.edge_target_offsets[0],
                        0x16200 + static_cast<std::uint64_t>(instruction_index)),
                    0x16300 + static_cast<std::uint64_t>(instruction_index));

      llvm::IRBuilder<> false_builder(false_block);
      apply_edge_assignments(false_builder, slot_allocas, current_slot_mapping,
                             program, instruction.edges[1], opaque_seed,
                             opaque_seed_base, mba_context,
                             0x16400 + static_cast<std::uint64_t>(instruction_index));
      rotate_to_mapping(false_builder,
                        program.blocks[instruction.edges[1].target_block]
                            .first_instruction);
      emit_dispatch(false_builder,
                    decode_target_dispatch(
                        false_builder, layout.edge_target_offsets[1],
                        0x16500 + static_cast<std::uint64_t>(instruction_index)),
                    0x16600 + static_cast<std::uint64_t>(instruction_index));
      break;
    }
    case opcode::switch_op: {
      auto *default_block = llvm::BasicBlock::Create(
          context, "vm.switch.default." + std::to_string(instruction_index), &function);
      auto *switch_inst = builder.CreateSwitch(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x17000 + static_cast<std::uint64_t>(instruction_index)),
          default_block, instruction.case_values.size());

      llvm::SmallVector<llvm::BasicBlock *, 8> case_blocks;
      case_blocks.reserve(instruction.case_values.size());
      for (std::size_t case_index = 0; case_index < instruction.case_values.size();
           ++case_index) {
        auto *case_block = llvm::BasicBlock::Create(
            context,
            "vm.switch.case." + std::to_string(instruction_index) + "." +
                std::to_string(case_index),
            &function);
        switch_inst->addCase(const_cast<llvm::ConstantInt *>(instruction.case_values[case_index]),
                             case_block);
        case_blocks.push_back(case_block);
      }

      llvm::IRBuilder<> default_builder(default_block);
      apply_edge_assignments(default_builder, slot_allocas, current_slot_mapping,
                             program, instruction.edges[0], opaque_seed,
                             opaque_seed_base, mba_context,
                             0x17100 + static_cast<std::uint64_t>(instruction_index));
      rotate_to_mapping(default_builder,
                        program.blocks[instruction.edges[0].target_block]
                            .first_instruction);
      emit_dispatch(default_builder,
                    decode_target_dispatch(
                        default_builder, layout.edge_target_offsets[0],
                        0x17200 + static_cast<std::uint64_t>(instruction_index)),
                    0x17300 + static_cast<std::uint64_t>(instruction_index));

      for (std::size_t case_index = 0; case_index < case_blocks.size(); ++case_index) {
        llvm::IRBuilder<> case_builder(case_blocks[case_index]);
        apply_edge_assignments(case_builder, slot_allocas, current_slot_mapping,
                               program, instruction.edges[case_index + 1], opaque_seed,
                               opaque_seed_base, mba_context,
                               0x17400 + static_cast<std::uint64_t>(instruction_index) * 8 +
                                   case_index);
        rotate_to_mapping(case_builder,
                          program.blocks[instruction.edges[case_index + 1].target_block]
                              .first_instruction);
        emit_dispatch(case_builder,
                      decode_target_dispatch(
                          case_builder, layout.edge_target_offsets[case_index + 1],
                          0x17500 +
                              static_cast<std::uint64_t>(instruction_index) * 8 +
                              case_index),
                      0x17600 + static_cast<std::uint64_t>(instruction_index) * 8 +
                          case_index);
      }
      break;
    }
    case opcode::unreachable_op:
      builder.CreateBr(trap_block);
      break;
    case opcode::ret:
      if (instruction.operands.empty()) {
        builder.CreateRetVoid();
      } else {
        llvm::Value *ret_val =
            materialize_value(builder, slot_allocas, current_slot_mapping, program,
                              instruction.operands[0], opaque_seed,
                              opaque_seed_base, mba_context,
                              0x18000 + static_cast<std::uint64_t>(instruction_index));
        // Encode the return value if this function returns an integer type
        // and we have a retkey global.  Encoding:
        //   encoded = ret_val ^ trunc(retkey ^ (state ^ expected_state))
        // Under normal (untampered) execution state == expected_state, so the
        // poison term cancels and the caller sees ret_val ^ trunc(retkey).
        // If bytecode was tampered, state diverges and garbage propagates.
        if (retkey_global != nullptr && ret_val->getType()->isIntegerTy()) {
          const std::uint64_t ret_salt =
              0x1a000 + static_cast<std::uint64_t>(instruction_index) * 16;
          auto *state_load = builder.CreateLoad(builder.getInt64Ty(), state_slot,
                                                "obf.vm.ret.state");
          auto *expected_const = builder.getInt64(
              serialized.layouts[instruction_index].expected_post_header_state);
          llvm::Value *poison = mba::create_xor(
              builder, state_load, expected_const, mba_context,
              ret_salt + 1, "obf.vm.ret.poison");
          auto *retkey_load = builder.CreateLoad(builder.getInt64Ty(),
                                                 retkey_global,
                                                 "obf.vm.ret.retkey");
          llvm::Value *full_key = mba::create_xor(
              builder, retkey_load, poison, mba_context,
              ret_salt + 2, "obf.vm.ret.fullkey");
          llvm::Value *key_trunc = full_key;
          if (ret_val->getType() != builder.getInt64Ty()) {
            key_trunc = builder.CreateTrunc(full_key, ret_val->getType(),
                                            "obf.vm.ret.key.trunc");
          }
          ret_val = mba::create_xor(
              builder, ret_val, key_trunc, mba_context,
              ret_salt + 3, "obf.vm.ret.encoded");
        }
        builder.CreateRet(ret_val);
      }
      break;
    }
  }

  llvm::IRBuilder<> trap_builder(trap_block);
  llvm::FunctionCallee trap = llvm::Intrinsic::getOrInsertDeclaration(
      function.getParent(), llvm::Intrinsic::trap);
  trap_builder.CreateCall(trap);
  trap_builder.CreateUnreachable();
}

} // namespace

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
