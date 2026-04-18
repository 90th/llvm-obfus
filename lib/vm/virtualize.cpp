#include "obf/vm/virtualize.h"

#include "obf/transforms/mba.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
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
#include "llvm/Support/ErrorHandling.h"

#include <array>
#include <bit>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <numeric>
#include <random>
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
inline constexpr std::size_t vm_opcode_count =
    static_cast<std::size_t>(opcode::ret) + 1;

enum class dispatch_backend_variant : std::uint32_t {
  switch_index = 0,
  direct_threaded_match = 1,
  direct_threaded_switch = 2,
};

inline constexpr std::size_t vm_switch_dispatch_min_instruction_count = 16;

struct opcode_permutation {
  std::array<std::uint8_t, vm_opcode_count> physical_for_logical = {};
};

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt);
std::uint64_t derive_vm_bytecode_seed(const llvm::Function &function,
                                      const bytecode_program &program);

std::size_t opcode_to_index(opcode op) {
  return static_cast<std::size_t>(op);
}

bool is_binary_opcode(opcode op) {
  switch (op) {
  case opcode::add:
  case opcode::sub:
  case opcode::mul:
  case opcode::udiv:
  case opcode::sdiv:
  case opcode::urem:
  case opcode::srem:
  case opcode::shl:
  case opcode::lshr:
  case opcode::ashr:
  case opcode::and_op:
  case opcode::or_op:
  case opcode::xor_op:
  case opcode::fadd:
  case opcode::fsub:
  case opcode::fmul:
  case opcode::fdiv:
  case opcode::frem:
    return true;
  default:
    return false;
  }
}

bool is_cast_opcode(opcode op) {
  switch (op) {
  case opcode::trunc:
  case opcode::zext:
  case opcode::sext:
  case opcode::fp_trunc:
  case opcode::fp_ext:
  case opcode::ui_to_fp:
  case opcode::si_to_fp:
  case opcode::fp_to_ui:
  case opcode::fp_to_si:
  case opcode::ptr_to_int:
  case opcode::int_to_ptr:
  case opcode::bitcast:
  case opcode::addrspace_cast:
    return true;
  default:
    return false;
  }
}

bool is_icmp_opcode(opcode op) {
  switch (op) {
  case opcode::icmp_eq:
  case opcode::icmp_ne:
  case opcode::icmp_ugt:
  case opcode::icmp_uge:
  case opcode::icmp_ult:
  case opcode::icmp_ule:
  case opcode::icmp_sgt:
  case opcode::icmp_sge:
  case opcode::icmp_slt:
  case opcode::icmp_sle:
    return true;
  default:
    return false;
  }
}

bool is_fcmp_opcode(opcode op) {
  switch (op) {
  case opcode::fcmp_false:
  case opcode::fcmp_oeq:
  case opcode::fcmp_ogt:
  case opcode::fcmp_oge:
  case opcode::fcmp_olt:
  case opcode::fcmp_ole:
  case opcode::fcmp_one:
  case opcode::fcmp_ord:
  case opcode::fcmp_uno:
  case opcode::fcmp_ueq:
  case opcode::fcmp_ugt:
  case opcode::fcmp_uge:
  case opcode::fcmp_ult:
  case opcode::fcmp_ule:
  case opcode::fcmp_une:
  case opcode::fcmp_true:
    return true;
  default:
    return false;
  }
}

llvm::CmpInst::Predicate icmp_predicate_for_opcode(opcode op) {
  if (!is_icmp_opcode(op)) {
    llvm_unreachable("opcode is not an icmp predicate");
  }

  switch (op) {
  case opcode::icmp_eq:
    return llvm::CmpInst::ICMP_EQ;
  case opcode::icmp_ne:
    return llvm::CmpInst::ICMP_NE;
  case opcode::icmp_ugt:
    return llvm::CmpInst::ICMP_UGT;
  case opcode::icmp_uge:
    return llvm::CmpInst::ICMP_UGE;
  case opcode::icmp_ult:
    return llvm::CmpInst::ICMP_ULT;
  case opcode::icmp_ule:
    return llvm::CmpInst::ICMP_ULE;
  case opcode::icmp_sgt:
    return llvm::CmpInst::ICMP_SGT;
  case opcode::icmp_sge:
    return llvm::CmpInst::ICMP_SGE;
  case opcode::icmp_slt:
    return llvm::CmpInst::ICMP_SLT;
  case opcode::icmp_sle:
    return llvm::CmpInst::ICMP_SLE;
  default:
    llvm_unreachable("opcode is not an icmp predicate");
  }
}

llvm::CmpInst::Predicate fcmp_predicate_for_opcode(opcode op) {
  if (!is_fcmp_opcode(op)) {
    llvm_unreachable("opcode is not an fcmp predicate");
  }

  switch (op) {
  case opcode::fcmp_false:
    return llvm::CmpInst::FCMP_FALSE;
  case opcode::fcmp_oeq:
    return llvm::CmpInst::FCMP_OEQ;
  case opcode::fcmp_ogt:
    return llvm::CmpInst::FCMP_OGT;
  case opcode::fcmp_oge:
    return llvm::CmpInst::FCMP_OGE;
  case opcode::fcmp_olt:
    return llvm::CmpInst::FCMP_OLT;
  case opcode::fcmp_ole:
    return llvm::CmpInst::FCMP_OLE;
  case opcode::fcmp_one:
    return llvm::CmpInst::FCMP_ONE;
  case opcode::fcmp_ord:
    return llvm::CmpInst::FCMP_ORD;
  case opcode::fcmp_uno:
    return llvm::CmpInst::FCMP_UNO;
  case opcode::fcmp_ueq:
    return llvm::CmpInst::FCMP_UEQ;
  case opcode::fcmp_ugt:
    return llvm::CmpInst::FCMP_UGT;
  case opcode::fcmp_uge:
    return llvm::CmpInst::FCMP_UGE;
  case opcode::fcmp_ult:
    return llvm::CmpInst::FCMP_ULT;
  case opcode::fcmp_ule:
    return llvm::CmpInst::FCMP_ULE;
  case opcode::fcmp_une:
    return llvm::CmpInst::FCMP_UNE;
  case opcode::fcmp_true:
    return llvm::CmpInst::FCMP_TRUE;
  default:
    llvm_unreachable("opcode is not an fcmp predicate");
  }
}

std::uint32_t select_handler_variant(opcode op, std::uint64_t seed_base,
                                     std::uint64_t salt,
                                     std::uint32_t variant_count = 2) {
  if (variant_count <= 1) {
    return 0;
  }

  return static_cast<std::uint32_t>(
      mix_seed(seed_base,
               salt ^ ((static_cast<std::uint64_t>(opcode_to_index(op)) + 1) *
                       0x9e3779b97f4a7c15ULL)) %
      variant_count);
}

std::uint32_t select_dispatch_variant(std::uint64_t seed_base, std::uint64_t salt,
                                      std::size_t instruction_count,
                                      std::uint32_t variant_count = 3) {
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

struct bytecode_header_chunk {
  std::uint32_t offset = 0;
  std::uint8_t size = 0;
  bool carries_opcode = false;
};

struct pending_bytecode_header_chunk {
  std::array<std::uint8_t, 4> decoded_bytes = {};
  std::uint64_t order_key = 0;
  std::uint8_t size = 0;
  bool carries_opcode = false;
};

struct bytecode_layout {
  std::uint32_t header_offset = 0;
  std::vector<bytecode_header_chunk> header_chunks;
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

serialized_bytecode_program serialize_bytecode_program(
    const bytecode_program &program,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    llvm::ArrayRef<std::uint64_t> entry_states, std::uint64_t seed_base,
    const opcode_permutation &opcode_map) {
  serialized_bytecode_program serialized;
  serialized.layouts.resize(program.instructions.size());

  for (std::size_t instruction_index = 0;
       instruction_index < program.instructions.size(); ++instruction_index) {
    const micro_instruction &instruction = program.instructions[instruction_index];
    bytecode_layout &layout = serialized.layouts[instruction_index];
    layout.header_offset = static_cast<std::uint32_t>(serialized.bytes.size());

    std::uint64_t header_state = entry_states[instruction_index];
    std::vector<pending_bytecode_header_chunk> header_chunks;
    header_chunks.reserve(10 + instruction.operands.size() * 2);

    std::uint64_t chunk_ordinal = 0;
    const auto next_header_order_key = [&](std::uint64_t salt) {
      return mix_seed(
          seed_base,
          salt ^
              (static_cast<std::uint64_t>(instruction_index + 1) *
               0x9e3779b97f4a7c15ULL) ^
              (++chunk_ordinal * 0x517cc1b727220a95ULL));
    };
    const auto append_header_u8 = [&](std::uint8_t decoded, std::uint64_t salt,
                                      bool carries_opcode = false) {
      pending_bytecode_header_chunk chunk;
      chunk.decoded_bytes[0] = decoded;
      chunk.order_key = next_header_order_key(salt ^ decoded);
      chunk.size = 1;
      chunk.carries_opcode = carries_opcode;
      header_chunks.push_back(chunk);
    };
    const auto append_header_u32 = [&](std::uint32_t decoded,
                                       std::uint64_t salt) {
      pending_bytecode_header_chunk chunk;
      for (unsigned byte_index = 0; byte_index < 4; ++byte_index) {
        chunk.decoded_bytes[byte_index] =
            static_cast<std::uint8_t>(decoded >> (byte_index * 8));
      }
      chunk.order_key = next_header_order_key(salt ^ decoded);
      chunk.size = 4;
      header_chunks.push_back(chunk);
    };

    append_header_u8(get_physical_opcode(opcode_map, instruction.op), 0x4100,
                     /*carries_opcode=*/true);
    append_header_u32(instruction.subtype, 0x4200);
    append_header_u32(instruction.flags, 0x4300);
    append_header_u32(instruction.immediate, 0x4400);
    append_header_u32(instruction.result_slot, 0x4500);
    append_header_u8(static_cast<std::uint8_t>(instruction.operands.size()), 0x4600);
    for (const value_ref &operand : instruction.operands) {
      const std::uint64_t operand_salt =
          0x4700 + static_cast<std::uint64_t>(&operand - instruction.operands.data()) * 2;
      append_header_u8(static_cast<std::uint8_t>(operand.kind), operand_salt);
      append_header_u32(value_descriptor(operand), operand_salt + 1);
    }
    append_header_u8(static_cast<std::uint8_t>(instruction.edges.size()), 0x4800);

    const std::uint32_t junk_chunk_count =
        1U + static_cast<std::uint32_t>(
                 mix_seed(seed_base, 0x4d4554410000ULL + instruction_index) % 3ULL);
    for (std::uint32_t junk_index = 0; junk_index < junk_chunk_count; ++junk_index) {
      pending_bytecode_header_chunk chunk;
      chunk.size = static_cast<std::uint8_t>(
          1U + mix_seed(seed_base,
                        0x4d4554411000ULL +
                            static_cast<std::uint64_t>(instruction_index) * 8 +
                            junk_index) %
                    4ULL);
      chunk.order_key = next_header_order_key(0x4d4554412000ULL + junk_index);
      for (std::uint8_t byte_index = 0; byte_index < chunk.size; ++byte_index) {
        chunk.decoded_bytes[byte_index] = static_cast<std::uint8_t>(
            mix_seed(seed_base,
                     0x4d4554413000ULL +
                         static_cast<std::uint64_t>(instruction_index) * 16 +
                         static_cast<std::uint64_t>(junk_index) * 4 + byte_index) &
            0xffU);
      }
      header_chunks.push_back(chunk);
    }

    // Shuffle real metadata fields with junk so the bytecode header has no
    // stable field order.
    std::stable_sort(
        header_chunks.begin(), header_chunks.end(),
        [](const pending_bytecode_header_chunk &lhs,
           const pending_bytecode_header_chunk &rhs) {
          return lhs.order_key < rhs.order_key;
        });
    layout.header_chunks.reserve(header_chunks.size());
    for (const pending_bytecode_header_chunk &chunk : header_chunks) {
      layout.header_chunks.push_back(
          {.offset = static_cast<std::uint32_t>(serialized.bytes.size()),
           .size = chunk.size,
           .carries_opcode = chunk.carries_opcode});
      for (unsigned byte_index = 0; byte_index < chunk.size; ++byte_index) {
        append_encoded_u8(serialized.bytes, chunk.decoded_bytes[byte_index],
                          header_state, seed_base);
      }
    }

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

llvm::Value *materialize_integer_constant(llvm::IRBuilder<> &builder,
                                          const llvm::ConstantInt &integer,
                                          llvm::AllocaInst *opaque_seed_slot,
                                          std::uint64_t opaque_seed_base,
                                          const mba::builder_context &mba_context,
                                          std::uint64_t salt) {
  if (!should_obfuscate_vm_constant(integer)) {
    return const_cast<llvm::ConstantInt *>(&integer);
  }

  const llvm::APInt &value = integer.getValue();
  const std::uint64_t constant_salt =
      static_cast<std::uint64_t>(value.getBitWidth()) * 131ULL;
  const std::uint64_t word = value.getLimitedValue();
  const llvm::APInt key(value.getBitWidth(),
                        (word ^ 0x9e3779b97f4a7c15ULL) + constant_salt,
                        /*isSigned=*/false, /*implicitTrunc=*/true);
  const llvm::APInt encoded = value ^ key;
  llvm::Value *mask = build_opaque_vm_mask(
      builder, opaque_seed_slot, opaque_seed_base,
      llvm::cast<llvm::IntegerType>(integer.getType()), key, mba_context,
      salt ^ constant_salt ^ 0x13579bdfULL);
  return mba::create_xor(builder,
                         llvm::ConstantInt::get(integer.getType(), encoded),
                         mask, mba_context, salt ^ constant_salt ^ 0x2468ace0ULL,
                         "obf.vm.const");
}

const llvm::DataLayout *get_builder_data_layout(const llvm::IRBuilder<> &builder) {
  const llvm::BasicBlock *block = builder.GetInsertBlock();
  const llvm::Function *function = block != nullptr ? block->getParent() : nullptr;
  const llvm::Module *module = function != nullptr ? function->getParent() : nullptr;
  return module != nullptr ? &module->getDataLayout() : nullptr;
}

bool can_materialize_pointer_through_integer(const llvm::DataLayout &data_layout,
                                             const llvm::Type *type) {
  const auto *pointer_type = llvm::dyn_cast<llvm::PointerType>(type);
  return pointer_type != nullptr &&
         !data_layout.isNonIntegralPointerType(
             const_cast<llvm::PointerType *>(pointer_type));
}

llvm::IntegerType *get_pointer_carrier_type(llvm::IRBuilder<> &builder,
                                            llvm::Type *type) {
  const llvm::DataLayout *data_layout = get_builder_data_layout(builder);
  if (data_layout == nullptr ||
      !can_materialize_pointer_through_integer(*data_layout, type)) {
    return nullptr;
  }

  const auto *pointer_type = llvm::cast<llvm::PointerType>(type);
  return data_layout->getIntPtrType(builder.getContext(),
                                    pointer_type->getAddressSpace());
}

llvm::GlobalVariable *get_or_create_pointer_constant_cell(
    llvm::Module &module, const llvm::Constant &constant) {
  const std::string global_name =
      ("__obf_vm_ptrconst_" +
       llvm::utohexstr(static_cast<std::uint64_t>(llvm::hash_value(&constant))));
  if (llvm::GlobalVariable *existing = module.getNamedGlobal(global_name)) {
    if (existing->getValueType() != constant.getType()) {
      llvm_unreachable("vm pointer constant cell has unexpected type");
    }
    return existing;
  }

  auto *cell = new llvm::GlobalVariable(module, const_cast<llvm::Type *>(constant.getType()),
                                        /*isConstant=*/true,
                                        llvm::GlobalValue::PrivateLinkage,
                                        const_cast<llvm::Constant *>(&constant),
                                        global_name);
  cell->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  return cell;
}

llvm::Value *materialize_pointer_carrier(
    llvm::IRBuilder<> &builder, llvm::Value *pointer_value,
    llvm::AllocaInst *opaque_seed_slot, std::uint64_t opaque_seed_base,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *carrier_type = get_pointer_carrier_type(builder, pointer_value->getType());
  if (carrier_type == nullptr) {
    return nullptr;
  }

  if (const auto *pointer_constant = llvm::dyn_cast<llvm::Constant>(pointer_value)) {
    llvm::BasicBlock *block = builder.GetInsertBlock();
    llvm::Function *function = block != nullptr ? block->getParent() : nullptr;
    llvm::Module *module = function != nullptr ? function->getParent() : nullptr;
    if (module != nullptr) {
      llvm::GlobalVariable *pointer_cell =
          get_or_create_pointer_constant_cell(*module, *pointer_constant);
      pointer_value = builder.CreateLoad(
          const_cast<llvm::Type *>(pointer_constant->getType()), pointer_cell,
          "obf.vm.ptr.const");
    }
  }

  llvm::Value *raw_carrier =
      builder.CreatePtrToInt(pointer_value, carrier_type, "obf.vm.ptr.raw");
  if (const auto *carrier_integer = llvm::dyn_cast<llvm::ConstantInt>(raw_carrier)) {
    return materialize_integer_constant(builder, *carrier_integer, opaque_seed_slot,
                                        opaque_seed_base, mba_context,
                                        salt ^ 0x5101ULL);
  }

  return mba::entangle_value(builder, raw_carrier, mba_context,
                             salt ^ 0x5202ULL, "obf.vm.ptr.carrier");
}

llvm::Value *materialize_pointer_value(llvm::IRBuilder<> &builder,
                                       llvm::Value *pointer_value,
                                       llvm::AllocaInst *opaque_seed_slot,
                                       std::uint64_t opaque_seed_base,
                                       const mba::builder_context &mba_context,
                                       std::uint64_t salt) {
  auto *pointer_type = llvm::dyn_cast<llvm::PointerType>(pointer_value->getType());
  if (pointer_type == nullptr) {
    return nullptr;
  }

  llvm::Value *carrier =
      materialize_pointer_carrier(builder, pointer_value, opaque_seed_slot,
                                  opaque_seed_base, mba_context,
                                  salt ^ 0x5303ULL);
  if (carrier == nullptr) {
    return nullptr;
  }

  return builder.CreateIntToPtr(carrier, pointer_type, "obf.vm.ptr");
}

llvm::Value *materialize_constant(llvm::IRBuilder<> &builder,
                                  const llvm::Constant &constant,
                                  llvm::AllocaInst *opaque_seed_slot,
                                  std::uint64_t opaque_seed_base,
                                  const mba::builder_context &mba_context,
                                  std::uint64_t salt) {
  if (const auto *integer = llvm::dyn_cast<llvm::ConstantInt>(&constant)) {
    return materialize_integer_constant(builder, *integer, opaque_seed_slot,
                                        opaque_seed_base, mba_context, salt);
  }

  if (constant.getType()->isPointerTy()) {
    if (llvm::Value *pointer_value = materialize_pointer_value(
            builder, const_cast<llvm::Constant *>(&constant), opaque_seed_slot,
            opaque_seed_base, mba_context, salt ^ 0x5404ULL)) {
      return pointer_value;
    }
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
    llvm::Value *slot_value =
        load_slot(builder, slot_allocas, slot_mapping, program, value.slot);
    if (slot_value->getType()->isPointerTy()) {
      if (llvm::Value *pointer_value = materialize_pointer_value(
              builder, slot_value, opaque_seed_slot, opaque_seed_base,
              mba_context, salt ^ 0x5505ULL)) {
        return pointer_value;
      }
    }

    return slot_value;
  }

  return materialize_constant(builder, *value.constant, opaque_seed_slot,
                              opaque_seed_base, mba_context, salt);
}

const llvm::Type *value_ref_type(const bytecode_program &program,
                                 const value_ref &value) {
  if (value.kind == value_ref_kind::slot) {
    return program.slots[value.slot].type;
  }

  return value.constant->getType();
}

llvm::Value *materialize_pointer_carrier_from_value_ref(
    llvm::IRBuilder<> &builder, const slot_storage &slot_allocas,
    llvm::ArrayRef<std::uint32_t> slot_mapping, const bytecode_program &program,
    const value_ref &value, llvm::AllocaInst *opaque_seed_slot,
    std::uint64_t opaque_seed_base, const mba::builder_context &mba_context,
    std::uint64_t salt) {
  if (!value_ref_type(program, value)->isPointerTy()) {
    return nullptr;
  }

  llvm::Value *pointer_value = nullptr;
  if (value.kind == value_ref_kind::slot) {
    pointer_value =
        load_slot(builder, slot_allocas, slot_mapping, program, value.slot);
  } else {
    pointer_value = const_cast<llvm::Constant *>(value.constant);
  }

  return materialize_pointer_carrier(builder, pointer_value, opaque_seed_slot,
                                     opaque_seed_base, mba_context, salt);
}

llvm::Value *emit_integer_nonzero_test(
    llvm::IRBuilder<> &builder, llvm::Value *value,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(value->getType());
  llvm::Value *negated = mba::create_sub(
      builder, llvm::ConstantInt::get(integer_type, 0), value, mba_context,
      salt + 1, "obf.vm.icmp.nz.neg");
  llvm::Value *combined = builder.CreateOr(value, negated, "obf.vm.icmp.nz.or");
  llvm::Value *top_bit = builder.CreateLShr(
      combined, llvm::ConstantInt::get(integer_type,
                                       integer_type->getBitWidth() - 1),
      "obf.vm.icmp.nz.sh");
  return builder.CreateTrunc(top_bit, builder.getInt1Ty(), "obf.vm.icmp.nz");
}

llvm::Value *emit_integer_unsigned_lt(
    llvm::IRBuilder<> &builder, llvm::Value *lhs, llvm::Value *rhs,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(lhs->getType());
  auto *wide_type = llvm::IntegerType::get(builder.getContext(),
                                           integer_type->getBitWidth() + 1);
  llvm::Value *lhs_ext = builder.CreateZExt(lhs, wide_type, "obf.vm.icmp.ult.lhs");
  llvm::Value *rhs_ext = builder.CreateZExt(rhs, wide_type, "obf.vm.icmp.ult.rhs");
  llvm::Value *diff = mba::create_sub(builder, lhs_ext, rhs_ext, mba_context,
                                      salt + 1, "obf.vm.icmp.ult.diff");
  llvm::Value *borrow = builder.CreateLShr(
      diff,
      llvm::ConstantInt::get(wide_type, integer_type->getBitWidth()),
      "obf.vm.icmp.ult.borrow");
  return builder.CreateTrunc(borrow, builder.getInt1Ty(), "obf.vm.icmp.ult");
}

llvm::Value *emit_integer_icmp(llvm::IRBuilder<> &builder, opcode predicate,
                               llvm::Value *lhs, llvm::Value *rhs,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *integer_type = llvm::cast<llvm::IntegerType>(lhs->getType());
  llvm::Value *result = nullptr;
  switch (predicate) {
  case opcode::icmp_eq:
  case opcode::icmp_ne: {
    llvm::Value *difference = mba::create_xor(builder, lhs, rhs, mba_context,
                                              salt + 1, "obf.vm.icmp.eq.diff");
    llvm::Value *nonzero = emit_integer_nonzero_test(builder, difference,
                                                     mba_context, salt + 2);
    result = predicate == opcode::icmp_ne
                 ? nonzero
                 : builder.CreateXor(nonzero, builder.getTrue(),
                                     "obf.vm.icmp.eq");
    break;
  }
  case opcode::icmp_ult:
    result = emit_integer_unsigned_lt(builder, lhs, rhs, mba_context, salt + 3);
    break;
  case opcode::icmp_ugt:
    result = emit_integer_unsigned_lt(builder, rhs, lhs, mba_context, salt + 4);
    break;
  case opcode::icmp_ule:
    result = builder.CreateXor(
        emit_integer_unsigned_lt(builder, rhs, lhs, mba_context, salt + 5),
        builder.getTrue(), "obf.vm.icmp.ule");
    break;
  case opcode::icmp_uge:
    result = builder.CreateXor(
        emit_integer_unsigned_lt(builder, lhs, rhs, mba_context, salt + 6),
        builder.getTrue(), "obf.vm.icmp.uge");
    break;
  case opcode::icmp_slt:
  case opcode::icmp_sgt:
  case opcode::icmp_sle:
  case opcode::icmp_sge: {
    llvm::Constant *sign_mask = llvm::ConstantInt::get(
        integer_type, llvm::APInt::getSignMask(integer_type->getBitWidth()));
    llvm::Value *lhs_biased = mba::create_xor(builder, lhs, sign_mask,
                                              mba_context, salt + 7,
                                              "obf.vm.icmp.signed.lhs");
    llvm::Value *rhs_biased = mba::create_xor(builder, rhs, sign_mask,
                                              mba_context, salt + 8,
                                              "obf.vm.icmp.signed.rhs");
    switch (predicate) {
    case opcode::icmp_slt:
      result = emit_integer_unsigned_lt(builder, lhs_biased, rhs_biased,
                                        mba_context, salt + 9);
      break;
    case opcode::icmp_sgt:
      result = emit_integer_unsigned_lt(builder, rhs_biased, lhs_biased,
                                        mba_context, salt + 10);
      break;
    case opcode::icmp_sle:
      result = builder.CreateXor(
          emit_integer_unsigned_lt(builder, rhs_biased, lhs_biased,
                                   mba_context, salt + 11),
          builder.getTrue(), "obf.vm.icmp.sle");
      break;
    case opcode::icmp_sge:
      result = builder.CreateXor(
          emit_integer_unsigned_lt(builder, lhs_biased, rhs_biased,
                                   mba_context, salt + 12),
          builder.getTrue(), "obf.vm.icmp.sge");
      break;
    default:
      llvm_unreachable("unexpected signed integer compare predicate");
    }
    break;
  }
  default:
    llvm_unreachable("opcode is not a scalar integer compare predicate");
  }

  return result;
}

llvm::Value *emit_integer_sign_recovery(llvm::IRBuilder<> &builder,
                                        llvm::Value *widened_value,
                                        unsigned source_bit_width,
                                        llvm::StringRef name_prefix) {
  auto *destination_type = llvm::cast<llvm::IntegerType>(widened_value->getType());
  if (source_bit_width >= destination_type->getBitWidth()) {
    return widened_value;
  }

  llvm::Value *shift_amount = llvm::ConstantInt::get(
      destination_type, destination_type->getBitWidth() - source_bit_width);
  llvm::Value *shifted =
      builder.CreateShl(widened_value, shift_amount, (name_prefix + ".shl").str());
  return builder.CreateAShr(shifted, shift_amount, name_prefix);
}

llvm::Value *emit_integer_zext(llvm::IRBuilder<> &builder, llvm::Value *operand,
                               llvm::IntegerType *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Constant *source_bias = llvm::ConstantInt::get(
      source_type,
      llvm::APInt::getOneBitSet(source_type->getBitWidth(),
                                source_type->getBitWidth() - 1));
  llvm::Value *biased = mba::create_xor(builder, operand, source_bias, mba_context,
                                        salt + 1, "obf.vm.zext.bias");
  llvm::Value *widened = builder.CreateZExt(biased, destination_type,
                                            "obf.vm.zext.wide");
  widened = mba::create_xor(builder, widened,
                            llvm::ConstantInt::get(destination_type, 0),
                            mba_context, salt + 2, "obf.vm.zext.mix");
  llvm::Value *signed_value = emit_integer_sign_recovery(
      builder, widened, source_type->getBitWidth(), "obf.vm.zext.signed");
  llvm::Constant *destination_bias = llvm::ConstantInt::get(
      destination_type,
      llvm::APInt::getOneBitSet(destination_type->getBitWidth(),
                                source_type->getBitWidth() - 1));
  return mba::create_add(builder, signed_value, destination_bias, mba_context,
                         salt + 3, "obf.vm.zext");
}

llvm::Value *emit_integer_sext(llvm::IRBuilder<> &builder, llvm::Value *operand,
                               llvm::IntegerType *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Value *widened = builder.CreateZExt(operand, destination_type,
                                            "obf.vm.sext.wide");
  widened = mba::create_xor(builder, widened,
                            llvm::ConstantInt::get(destination_type, 0),
                            mba_context, salt + 1, "obf.vm.sext.mix");
  return emit_integer_sign_recovery(builder, widened, source_type->getBitWidth(),
                                    "obf.vm.sext");
}

llvm::Value *emit_integer_trunc(llvm::IRBuilder<> &builder, llvm::Value *operand,
                                llvm::IntegerType *destination_type,
                                const mba::builder_context &mba_context,
                                std::uint64_t salt) {
  auto *source_type = llvm::cast<llvm::IntegerType>(operand->getType());
  llvm::Value *masked = builder.CreateAnd(
      operand,
      llvm::ConstantInt::get(
          source_type,
          llvm::APInt::getLowBitsSet(source_type->getBitWidth(),
                                     destination_type->getBitWidth())),
      "obf.vm.trunc.mask");
  if (destination_type->isIntegerTy(1)) {
    masked = mba::create_xor(builder, masked,
                             llvm::ConstantInt::get(source_type, 0), mba_context,
                             salt + 1, "obf.vm.trunc.mix");
    return emit_integer_nonzero_test(builder, masked, mba_context, salt + 2);
  }

  return builder.CreateTrunc(masked, destination_type, "obf.vm.trunc");
}

llvm::Value *emit_integer_cast(llvm::IRBuilder<> &builder, opcode cast_opcode,
                               llvm::Value *operand,
                               llvm::Type *destination_type,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  auto *source_type = llvm::dyn_cast<llvm::IntegerType>(operand->getType());
  auto *destination_integer_type =
      llvm::dyn_cast<llvm::IntegerType>(destination_type);
  if (source_type == nullptr || destination_integer_type == nullptr) {
    return nullptr;
  }

  switch (cast_opcode) {
  case opcode::trunc:
    if (source_type->getBitWidth() > destination_integer_type->getBitWidth()) {
      return emit_integer_trunc(builder, operand, destination_integer_type,
                                mba_context, salt + 1);
    }
    break;
  case opcode::zext:
    if (source_type->getBitWidth() < destination_integer_type->getBitWidth()) {
      return emit_integer_zext(builder, operand, destination_integer_type,
                               mba_context, salt + 2);
    }
    break;
  case opcode::sext:
    if (source_type->getBitWidth() < destination_integer_type->getBitWidth()) {
      return emit_integer_sext(builder, operand, destination_integer_type,
                               mba_context, salt + 3);
    }
    break;
  default:
    break;
  }

  return nullptr;
}

llvm::Value *emit_unsigned_integer_width_cast(
    llvm::IRBuilder<> &builder, llvm::Value *operand,
    llvm::IntegerType *destination_type,
    const mba::builder_context &mba_context, std::uint64_t salt) {
  auto *source_type = llvm::dyn_cast<llvm::IntegerType>(operand->getType());
  if (source_type == nullptr || destination_type == nullptr) {
    return nullptr;
  }

  if (source_type == destination_type) {
    return operand;
  }

  if (source_type->getBitWidth() < destination_type->getBitWidth()) {
    return emit_integer_zext(builder, operand, destination_type, mba_context,
                             salt + 1);
  }

  if (source_type->getBitWidth() > destination_type->getBitWidth()) {
    return emit_integer_trunc(builder, operand, destination_type, mba_context,
                              salt + 2);
  }

  return operand;
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
  if (!is_binary_opcode(instruction.op)) {
    llvm_unreachable("opcode is not a binary opcode");
  }

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
  const std::uint32_t variant =
      select_handler_variant(instruction.op, opaque_seed_base, salt);
  switch (instruction.op) {
  case opcode::add:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_add(builder, lhs, rhs, mba_context, salt + 3,
                               "obf.vm.add");
    } else if (variant == 0) {
      result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    } else if (lhs->getType()->isIntegerTy()) {
      llvm::Value *sum = builder.CreateAdd(lhs, rhs, "obf.vm.add.variant");
      result = builder.CreateAdd(
          sum,
          mba::create_opaque_integer(builder, llvm::cast<llvm::IntegerType>(sum->getType()),
                                     mba_context,
                                     llvm::APInt(sum->getType()->getIntegerBitWidth(), 0),
                                     salt + 0x41, "obf.vm.add.zero"),
          "obf.vm.add");
    } else {
      result = builder.CreateAdd(lhs, rhs, "obf.vm.add");
    }
    break;
  case opcode::sub:
    if (!has_instruction_flag(instruction.flags, instruction_flag_nsw) &&
        !has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
      result = mba::create_sub(builder, lhs, rhs, mba_context, salt + 4,
                               "obf.vm.sub");
    } else if (variant == 0) {
      result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    } else if (lhs->getType()->isIntegerTy()) {
      llvm::Value *diff = builder.CreateSub(lhs, rhs, "obf.vm.sub.variant");
      result = builder.CreateXor(
          diff,
          mba::create_opaque_integer(builder, llvm::cast<llvm::IntegerType>(diff->getType()),
                                     mba_context,
                                     llvm::APInt(diff->getType()->getIntegerBitWidth(), 0),
                                     salt + 0x42, "obf.vm.sub.zero"),
          "obf.vm.sub");
    } else {
      result = builder.CreateSub(lhs, rhs, "obf.vm.sub");
    }
    break;
  case opcode::mul:
    result = builder.CreateMul(lhs, rhs, "obf.vm.mul");
    break;
  case opcode::udiv:
    result = builder.CreateUDiv(lhs, rhs, "obf.vm.udiv");
    break;
  case opcode::sdiv:
    result = builder.CreateSDiv(lhs, rhs, "obf.vm.sdiv");
    break;
  case opcode::urem:
    result = builder.CreateURem(lhs, rhs, "obf.vm.urem");
    break;
  case opcode::srem:
    result = builder.CreateSRem(lhs, rhs, "obf.vm.srem");
    break;
  case opcode::shl:
    result = builder.CreateShl(lhs, rhs, "obf.vm.shl");
    break;
  case opcode::lshr:
    result = builder.CreateLShr(lhs, rhs, "obf.vm.lshr");
    break;
  case opcode::ashr:
    result = builder.CreateAShr(lhs, rhs, "obf.vm.ashr");
    break;
  case opcode::and_op:
    result = builder.CreateAnd(lhs, rhs, "obf.vm.and");
    break;
  case opcode::or_op:
    result = builder.CreateOr(lhs, rhs, "obf.vm.or");
    break;
  case opcode::xor_op:
    result = mba::create_xor(builder, lhs, rhs, mba_context, salt + 5,
                             "obf.vm.xor");
    break;
  case opcode::fadd:
    result = builder.CreateFAdd(lhs, rhs, "obf.vm.fadd");
    break;
  case opcode::fsub:
    result = builder.CreateFSub(lhs, rhs, "obf.vm.fsub");
    break;
  case opcode::fmul:
    result = builder.CreateFMul(lhs, rhs, "obf.vm.fmul");
    break;
  case opcode::fdiv:
    result = builder.CreateFDiv(lhs, rhs, "obf.vm.fdiv");
    break;
  case opcode::frem:
    result = builder.CreateFRem(lhs, rhs, "obf.vm.frem");
    break;
  default:
    llvm_unreachable("opcode is not a binary opcode");
  }

  auto *binary = llvm::cast<llvm::BinaryOperator>(result);
  if (has_instruction_flag(instruction.flags, instruction_flag_nsw)) {
    binary->setHasNoSignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_nuw)) {
    binary->setHasNoUnsignedWrap();
  }
  if (has_instruction_flag(instruction.flags, instruction_flag_exact)) {
    switch (instruction.op) {
    case opcode::udiv:
    case opcode::sdiv:
    case opcode::lshr:
    case opcode::ashr:
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
  if (!is_cast_opcode(instruction.op)) {
    llvm_unreachable("opcode is not a cast opcode");
  }

  llvm::Type *const destination_type =
      const_cast<llvm::Type *>(program.slots[instruction.result_slot].type);
  const llvm::Type *const source_type =
      value_ref_type(program, instruction.operands[0]);

  llvm::Value *operand = nullptr;
  const auto materialize_operand = [&]() -> llvm::Value * {
    if (operand == nullptr) {
      operand = materialize_value(builder, slot_allocas, slot_mapping, program,
                                  instruction.operands[0], opaque_seed_slot,
                                  opaque_seed_base, mba_context, salt + 1);
    }

    return operand;
  };

  if (instruction.op == opcode::ptr_to_int && source_type->isPointerTy() &&
      destination_type->isIntegerTy()) {
    if (llvm::Value *carrier = materialize_pointer_carrier_from_value_ref(
            builder, slot_allocas, slot_mapping, program,
            instruction.operands[0], opaque_seed_slot, opaque_seed_base,
            mba_context, salt + 2)) {
      return emit_unsigned_integer_width_cast(
          builder, carrier, llvm::cast<llvm::IntegerType>(destination_type),
          mba_context, salt + 3);
    }
  }

  if (instruction.op == opcode::int_to_ptr && destination_type->isPointerTy()) {
    llvm::Value *source_integer = materialize_operand();
    if (auto *carrier_type = get_pointer_carrier_type(builder, destination_type)) {
      if (llvm::Value *carrier = emit_unsigned_integer_width_cast(
              builder, source_integer, carrier_type, mba_context, salt + 4)) {
        carrier = mba::entangle_value(builder, carrier, mba_context,
                                      salt ^ 0x5606ULL,
                                      "obf.vm.inttoptr.carrier");
        return builder.CreateIntToPtr(carrier, destination_type,
                                      "obf.vm.inttoptr");
      }
    }
  }

  if (instruction.op == opcode::bitcast && source_type->isPointerTy() &&
      destination_type->isPointerTy()) {
    if (llvm::Value *carrier = materialize_pointer_carrier_from_value_ref(
            builder, slot_allocas, slot_mapping, program,
            instruction.operands[0], opaque_seed_slot, opaque_seed_base,
            mba_context, salt + 5)) {
      if (auto *carrier_type = get_pointer_carrier_type(builder, destination_type)) {
        if (llvm::Value *normalized = emit_unsigned_integer_width_cast(
                builder, carrier, carrier_type, mba_context, salt + 6)) {
          return builder.CreateIntToPtr(normalized, destination_type,
                                        "obf.vm.bitcast");
        }
      }
    }
  }

  llvm::Value *const materialized_operand = materialize_operand();

  if (llvm::Value *integer_cast = emit_integer_cast(
          builder, instruction.op, materialized_operand, destination_type,
          mba_context,
          salt + 2)) {
    return integer_cast;
  }

  switch (instruction.op) {
  case opcode::trunc:
    return builder.CreateTrunc(materialized_operand, destination_type,
                               "obf.vm.trunc");
  case opcode::zext:
    return builder.CreateZExt(materialized_operand, destination_type,
                              "obf.vm.zext");
  case opcode::sext:
    return builder.CreateSExt(materialized_operand, destination_type,
                              "obf.vm.sext");
  case opcode::fp_trunc:
    return builder.CreateFPTrunc(materialized_operand, destination_type,
                                 "obf.vm.fptrunc");
  case opcode::fp_ext:
    return builder.CreateFPExt(materialized_operand, destination_type,
                               "obf.vm.fpext");
  case opcode::ui_to_fp:
    return builder.CreateUIToFP(materialized_operand, destination_type,
                                "obf.vm.uitofp");
  case opcode::si_to_fp:
    return builder.CreateSIToFP(materialized_operand, destination_type,
                                "obf.vm.sitofp");
  case opcode::fp_to_ui:
    return builder.CreateFPToUI(materialized_operand, destination_type,
                                "obf.vm.fptoui");
  case opcode::fp_to_si:
    return builder.CreateFPToSI(materialized_operand, destination_type,
                                "obf.vm.fptosi");
  case opcode::ptr_to_int:
    return builder.CreatePtrToInt(materialized_operand, destination_type,
                                  "obf.vm.ptrtoint");
  case opcode::int_to_ptr:
    return builder.CreateIntToPtr(materialized_operand, destination_type,
                                  "obf.vm.inttoptr");
  case opcode::bitcast:
    return builder.CreateBitCast(materialized_operand, destination_type,
                                 "obf.vm.bitcast");
  case opcode::addrspace_cast:
    return builder.CreateAddrSpaceCast(materialized_operand, destination_type,
                                       "obf.vm.addrspacecast");
  default:
    llvm_unreachable("opcode is not a cast opcode");
  }
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
  const opcode_permutation opcode_map =
      build_opcode_permutation(function, program);
  const dispatch_backend_variant dispatch_backend =
      static_cast<dispatch_backend_variant>(select_dispatch_variant(
          bytecode_seed, opaque_seed_base ^ 0x26000ULL,
          program.instructions.size()));
  const std::vector<std::uint32_t> dispatch_index_for_instruction =
      build_dispatch_index_map(program, bytecode_seed, dispatch_backend);
  const std::vector<std::uint64_t> entry_states =
      build_instruction_entry_states(program, bytecode_seed);
  const serialized_bytecode_program serialized = serialize_bytecode_program(
      program, dispatch_index_for_instruction, entry_states, bytecode_seed,
      opcode_map);

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
  // The caller-side rewriter looks this up by name to decode token-bound
  // return values.
  llvm::GlobalVariable *retkey_global = nullptr;
  if (function.getReturnType()->isIntegerTy()) {
    const std::uint64_t retkey_value =
        derive_vm_return_key(function, program);
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

  const auto build_switch_site_multiplier =
      [&](std::uint64_t salt) -> std::uint32_t {
    std::uint32_t multiplier = static_cast<std::uint32_t>(mix_seed(
        bytecode_seed, 0x5357495443482001ULL ^ salt));
    multiplier |= 1U;
    if (multiplier == 1U) {
      multiplier = 0x9e3779b1U;
    }
    return multiplier;
  };

  const auto build_switch_site_offset = [&](std::uint64_t salt) -> std::uint32_t {
    return static_cast<std::uint32_t>(mix_seed(
        bytecode_seed, 0x5357495443482002ULL ^ salt));
  };

  const auto remap_switch_dispatch_constant =
      [&](std::uint32_t dispatch_index, std::uint64_t salt) -> std::uint32_t {
    const std::uint32_t multiplier = build_switch_site_multiplier(salt);
    const std::uint32_t offset = build_switch_site_offset(salt);
    return static_cast<std::uint32_t>(
        static_cast<std::uint64_t>(dispatch_index) * multiplier + offset);
  };

  const auto remap_switch_dispatch_value =
      [&](llvm::IRBuilder<> &builder, llvm::Value *dispatch_index,
          std::uint64_t salt) -> llvm::Value * {
    const std::uint32_t multiplier = build_switch_site_multiplier(salt);
    const std::uint32_t offset = build_switch_site_offset(salt);
    llvm::Value *remapped = builder.CreateMul(
        dispatch_index, builder.getInt32(multiplier),
        "obf.vm.dispatch.index.site.mul");
    return builder.CreateAdd(remapped, builder.getInt32(offset),
                             "obf.vm.dispatch.index.site");
  };

  struct switch_dispatch_bank {
    llvm::BasicBlock *block = nullptr;
    llvm::PHINode *dispatch_index_phi = nullptr;
    std::uint64_t salt = 0;
  };

  constexpr std::size_t switch_dispatch_bank_count = 4;
  llvm::SmallVector<switch_dispatch_bank, switch_dispatch_bank_count>
      switch_dispatch_banks;
  if (!instruction_blocks.empty() &&
      dispatch_backend == dispatch_backend_variant::switch_index) {
    switch_dispatch_banks.reserve(switch_dispatch_bank_count);
    for (std::size_t bank_index = 0; bank_index < switch_dispatch_bank_count;
         ++bank_index) {
      const std::uint64_t bank_salt = 0x177000ULL + bank_index;
      auto *dispatch_switch_block = llvm::BasicBlock::Create(
          context,
          "dispatch.index.bank.obf.vm." + std::to_string(bank_index), &function);
      llvm::IRBuilder<> switch_builder(dispatch_switch_block);
      auto *dispatch_index_phi = switch_builder.CreatePHI(
          switch_builder.getInt32Ty(), 8, "obf.vm.dispatch.index.bank");
      llvm::Value *remapped_dispatch_index = remap_switch_dispatch_value(
          switch_builder, dispatch_index_phi, bank_salt);
      auto *switch_inst = switch_builder.CreateSwitch(
          remapped_dispatch_index, trap_block, instruction_blocks.size());
      for (std::size_t instruction_index = 0;
           instruction_index < instruction_blocks.size(); ++instruction_index) {
        switch_inst->addCase(
            switch_builder.getInt32(remap_switch_dispatch_constant(
                dispatch_index_for_instruction[instruction_index], bank_salt)),
            instruction_blocks[instruction_index]);
      }
      switch_dispatch_banks.push_back(
          {.block = dispatch_switch_block,
           .dispatch_index_phi = dispatch_index_phi,
           .salt = bank_salt});
    }
  }

  if (!instruction_blocks.empty() && dispatch_table != nullptr) {
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
    llvm::Value *bytecode_base = materialize_pointer_value(
        builder, bytecode_global, opaque_seed, opaque_seed_base, mba_context,
        salt ^ 0x5707ULL);
    if (bytecode_base == nullptr) {
      bytecode_base = bytecode_global;
    }

    llvm::Value *slot = builder.CreateInBoundsGEP(
        bytecode_global->getValueType(), bytecode_base,
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
                                    const bytecode_layout &layout,
                                    std::uint64_t salt) -> llvm::Value * {
    std::uint64_t local_salt = salt;
    llvm::Value *decoded_opcode = nullptr;
    for (const bytecode_header_chunk &chunk : layout.header_chunks) {
      if (chunk.carries_opcode) {
        decoded_opcode = fetch_byte(builder, chunk.offset, local_salt++);
        continue;
      }
      if (chunk.size == 4) {
        (void)fetch_u32(builder, chunk.offset, local_salt);
        local_salt += 4;
        continue;
      }
      for (std::uint32_t byte_index = 0; byte_index < chunk.size; ++byte_index) {
        (void)fetch_byte(builder, chunk.offset + byte_index, local_salt++);
      }
    }
    if (decoded_opcode != nullptr) {
      return decoded_opcode;
    }
    llvm_unreachable("serialized vm header missing opcode");
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
    if (dispatch_backend == dispatch_backend_variant::switch_index) {
      if (switch_dispatch_banks.empty()) {
        builder.CreateBr(trap_block);
        return;
      }

      llvm::BasicBlock *dispatch_source = builder.GetInsertBlock();
      const std::size_t bank_index = static_cast<std::size_t>(
          mix_seed(bytecode_seed, 0x5357495443483003ULL ^ salt) %
          switch_dispatch_banks.size());
      switch_dispatch_bank &bank = switch_dispatch_banks[bank_index];
      builder.CreateBr(bank.block);
      bank.dispatch_index_phi->addIncoming(dispatch_index, dispatch_source);
      return;
    }

    llvm::Value *in_range = builder.CreateICmpULT(
        dispatch_index,
        builder.getInt32(static_cast<std::uint32_t>(instruction_blocks.size())),
        "obf.vm.dispatch.inrange");

    auto *jump_block = llvm::BasicBlock::Create(
        context, "dispatch.jump.obf.vm." + std::to_string(dispatch_site_counter++),
        &function);
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

    if (dispatch_backend == dispatch_backend_variant::direct_threaded_match) {
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
      return;
    }

    auto *dispatch_switch_block = llvm::BasicBlock::Create(
        context, "dispatch.switch.obf.vm." + std::to_string(dispatch_site_counter++),
        &function);
    jump_builder.CreateBr(dispatch_switch_block);

    llvm::IRBuilder<> switch_builder(dispatch_switch_block);
    auto *emit_block = llvm::BasicBlock::Create(
        context, "dispatch.emit.obf.vm." + std::to_string(dispatch_site_counter++),
        &function);
    auto *switch_inst = switch_builder.CreateSwitch(
        dispatch_index, trap_block, instruction_blocks.size());

    llvm::SmallVector<llvm::BasicBlock *, 16> case_blocks;
    case_blocks.reserve(instruction_blocks.size());
    for (std::size_t instruction_index = 0;
         instruction_index < instruction_blocks.size(); ++instruction_index) {
      auto *case_block = llvm::BasicBlock::Create(
          context,
          "dispatch.case.obf.vm." + std::to_string(dispatch_site_counter++) + "." +
              std::to_string(instruction_index),
          &function);
      switch_inst->addCase(switch_builder.getInt32(
                               dispatch_index_for_instruction[instruction_index]),
                           case_block);
      case_blocks.push_back(case_block);
    }

    llvm::IRBuilder<> emit_builder(emit_block);
    auto *dispatch_target = emit_builder.CreatePHI(
        llvm::PointerType::get(context, function.getAddressSpace()),
        instruction_blocks.size(), "obf.vm.dispatch.target");
    auto *dispatch =
        emit_builder.CreateIndirectBr(dispatch_target, instruction_blocks.size());
    for (llvm::BasicBlock *instruction_block : instruction_blocks) {
      dispatch->addDestination(instruction_block);
    }

    for (std::size_t instruction_index = 0;
         instruction_index < instruction_blocks.size(); ++instruction_index) {
      llvm::BasicBlock *instruction_block = instruction_blocks[instruction_index];
      llvm::IRBuilder<> case_builder(case_blocks[instruction_index]);
      llvm::Constant *plain_target = llvm::ConstantExpr::getPtrToInt(
          llvm::BlockAddress::get(&function, instruction_block), ptr_int_type);
      llvm::Value *is_match = case_builder.CreateICmpEQ(
          decoded_target, plain_target, "obf.vm.dispatch.match");
      case_builder.CreateCondBr(is_match, emit_block, trap_block);
      dispatch_target->addIncoming(llvm::BlockAddress::get(&function, instruction_block),
                                   case_blocks[instruction_index]);
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
    llvm::IRBuilder<> header_builder(instruction_blocks[instruction_index]);
    const bytecode_layout &layout = serialized.layouts[instruction_index];
    const llvm::ArrayRef<std::uint32_t> current_slot_mapping(
        slot_mappings[instruction_index]);
    llvm::Value *decoded_opcode = consume_metadata(
        header_builder, layout,
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
        llvm::Value *bytecode_base = materialize_pointer_value(
            header_builder, bytecode_global, opaque_seed, opaque_seed_base,
            mba_context,
            0x5800 + static_cast<std::uint64_t>(instruction_index) * 4 + probe);
        if (bytecode_base == nullptr) {
          bytecode_base = bytecode_global;
        }
        llvm::Value *byte_ptr = header_builder.CreateInBoundsGEP(
            bytecode_global->getValueType(), bytecode_base,
            {header_builder.getInt32(0), header_builder.getInt32(probe_offset)},
            "obf.vm.integrity.ptr");
        llvm::Value *cipher_byte = header_builder.CreateLoad(
            header_builder.getInt8Ty(), byte_ptr, "obf.vm.integrity.byte");
        auto *integrity_state = header_builder.CreateLoad(
            header_builder.getInt64Ty(), state_slot, "obf.vm.integrity.state");
        llvm::Value *rotated = header_builder.CreateOr(
            header_builder.CreateLShr(integrity_state, header_builder.getInt64(7),
                                      "obf.vm.integrity.shr"),
            header_builder.CreateShl(integrity_state, header_builder.getInt64(57),
                                     "obf.vm.integrity.shl"),
            "obf.vm.integrity.rot");
        llvm::Value *extended = header_builder.CreateZExt(
            cipher_byte, header_builder.getInt64Ty(), "obf.vm.integrity.ext");
        llvm::Value *scaled = header_builder.CreateMul(
            extended, header_builder.getInt64(0x517cc1b727220a95ULL),
            "obf.vm.integrity.scale");
        llvm::Value *folded = header_builder.CreateXor(
            integrity_state,
            header_builder.CreateAdd(rotated, scaled, "obf.vm.integrity.sum"),
            "obf.vm.integrity.fold");
        (void)header_builder.CreateStore(folded, state_slot);
      }
    }

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

    const auto rotate_to_mapping = [&](llvm::IRBuilder<> &rotation_builder,
                                       std::uint32_t target_instruction) {
      if (target_instruction >= slot_mappings.size()) {
        return;
      }

      rotate_slot_cells(rotation_builder, slot_allocas, program,
                        current_slot_mapping,
                        llvm::ArrayRef<std::uint32_t>(slot_mappings[target_instruction]));
    };

    const auto finish_value_in_builder =
        [&](llvm::IRBuilder<> &finish_builder, llvm::Value *result) {
          if (instruction.result_slot != invalid_slot) {
            store_slot(finish_builder, slot_allocas, current_slot_mapping,
                       instruction.result_slot, result);
          }
          if (instruction_index + 1 < slot_mappings.size()) {
            rotate_to_mapping(finish_builder,
                              static_cast<std::uint32_t>(instruction_index + 1));
          }
          llvm::Value *next_target = decode_target_dispatch(
              finish_builder, layout.fallthrough_target_offset,
              0x9000 + static_cast<std::uint64_t>(instruction_index) * 32);
          emit_dispatch(finish_builder, next_target,
                        0xa000 + static_cast<std::uint64_t>(instruction_index) * 32);
        };

    const auto finish_value = [&](llvm::Value *result) {
      finish_value_in_builder(builder, result);
    };

    const auto emit_in_helper_block = [&](llvm::StringRef name, auto &&emit) {
      auto *helper_block = llvm::BasicBlock::Create(
          context, (name + std::to_string(instruction_index)).str(), &function);
      builder.CreateBr(helper_block);
      llvm::IRBuilder<> helper_builder(helper_block);
      emit(helper_builder);
    };

    switch (instruction.op) {
    case opcode::add:
    case opcode::sub:
    case opcode::mul:
    case opcode::udiv:
    case opcode::sdiv:
    case opcode::urem:
    case opcode::srem:
    case opcode::shl:
    case opcode::lshr:
    case opcode::ashr:
    case opcode::and_op:
    case opcode::or_op:
    case opcode::xor_op:
    case opcode::fadd:
    case opcode::fsub:
    case opcode::fmul:
    case opcode::fdiv:
    case opcode::frem:
      finish_value(emit_binary(builder, slot_allocas, current_slot_mapping,
                               program, instruction, opaque_seed,
                               opaque_seed_base, mba_context,
                               0xb000 + static_cast<std::uint64_t>(instruction_index)));
      break;
    case opcode::trunc:
    case opcode::zext:
    case opcode::sext:
    case opcode::fp_trunc:
    case opcode::fp_ext:
    case opcode::ui_to_fp:
    case opcode::si_to_fp:
    case opcode::fp_to_ui:
    case opcode::fp_to_si:
    case opcode::ptr_to_int:
    case opcode::int_to_ptr:
    case opcode::bitcast:
    case opcode::addrspace_cast:
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0xc800 + instruction_index) == 0) {
        finish_value(emit_cast(builder, slot_allocas, current_slot_mapping,
                               program, instruction, opaque_seed,
                               opaque_seed_base, mba_context,
                               0xc000 + static_cast<std::uint64_t>(instruction_index)));
      } else {
        emit_in_helper_block(
            "vm.cast.exec.", [&](llvm::IRBuilder<> &helper_builder) {
              finish_value_in_builder(
                  helper_builder,
                  emit_cast(helper_builder, slot_allocas, current_slot_mapping,
                            program, instruction, opaque_seed, opaque_seed_base,
                            mba_context,
                            0xc000 + static_cast<std::uint64_t>(instruction_index)));
            });
      }
      break;
    case opcode::freeze:
      finish_value(builder.CreateFreeze(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xd000 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.freeze"));
      break;
    case opcode::fneg: {
      auto *neg = llvm::cast<llvm::Instruction>(builder.CreateFNeg(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0xd080 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.fneg"));
      apply_fast_math_flags(neg, instruction.flags);
      finish_value(neg);
      break;
    }
    case opcode::icmp_eq:
    case opcode::icmp_ne:
    case opcode::icmp_ugt:
    case opcode::icmp_uge:
    case opcode::icmp_ult:
    case opcode::icmp_ule:
    case opcode::icmp_sgt:
    case opcode::icmp_sge:
    case opcode::icmp_slt:
    case opcode::icmp_sle:
      {
        const auto emit_compare = [&](llvm::IRBuilder<> &compare_builder) {
          llvm::Value *lhs = materialize_value(
              compare_builder, slot_allocas, current_slot_mapping, program,
              instruction.operands[0], opaque_seed, opaque_seed_base,
              mba_context,
              0xe000 + static_cast<std::uint64_t>(instruction_index));
          llvm::Value *rhs = materialize_value(
              compare_builder, slot_allocas, current_slot_mapping, program,
              instruction.operands[1], opaque_seed, opaque_seed_base,
              mba_context,
              0xe100 + static_cast<std::uint64_t>(instruction_index));
          if (lhs->getType()->isIntegerTy() && lhs->getType() == rhs->getType()) {
            return emit_integer_icmp(compare_builder, instruction.op, lhs, rhs,
                                     mba_context,
                                     0xe200 + static_cast<std::uint64_t>(instruction_index) *
                                                 16);
          }
          return compare_builder.CreateICmp(
              icmp_predicate_for_opcode(instruction.op), lhs, rhs,
              "obf.vm.icmp");
        };

        if (value_ref_type(program, instruction.operands[0])->isIntegerTy() &&
            value_ref_type(program, instruction.operands[0]) ==
                value_ref_type(program, instruction.operands[1])) {
          finish_value(emit_compare(builder));
        } else if (select_handler_variant(instruction.op, opaque_seed_base,
                                          0xe800 + instruction_index) == 0) {
          finish_value(emit_compare(builder));
        } else {
        emit_in_helper_block(
            "vm.icmp.exec.", [&](llvm::IRBuilder<> &helper_builder) {
              finish_value_in_builder(helper_builder, emit_compare(helper_builder));
            });
        }
      }
      break;
    case opcode::fcmp_false:
    case opcode::fcmp_oeq:
    case opcode::fcmp_ogt:
    case opcode::fcmp_oge:
    case opcode::fcmp_olt:
    case opcode::fcmp_ole:
    case opcode::fcmp_one:
    case opcode::fcmp_ord:
    case opcode::fcmp_uno:
    case opcode::fcmp_ueq:
    case opcode::fcmp_ugt:
    case opcode::fcmp_uge:
    case opcode::fcmp_ult:
    case opcode::fcmp_ule:
    case opcode::fcmp_une:
    case opcode::fcmp_true: {
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0xf800 + instruction_index) == 0) {
        auto *compare = llvm::cast<llvm::Instruction>(builder.CreateFCmp(
            fcmp_predicate_for_opcode(instruction.op),
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
      } else {
        emit_in_helper_block(
            "vm.fcmp.exec.", [&](llvm::IRBuilder<> &helper_builder) {
              auto *compare = llvm::cast<llvm::Instruction>(helper_builder.CreateFCmp(
                  fcmp_predicate_for_opcode(instruction.op),
                  materialize_value(helper_builder, slot_allocas,
                                    current_slot_mapping, program,
                                    instruction.operands[0], opaque_seed,
                                    opaque_seed_base, mba_context,
                                    0xf000 +
                                        static_cast<std::uint64_t>(instruction_index)),
                  materialize_value(helper_builder, slot_allocas,
                                    current_slot_mapping, program,
                                    instruction.operands[1], opaque_seed,
                                    opaque_seed_base, mba_context,
                                    0xf100 +
                                        static_cast<std::uint64_t>(instruction_index)),
                  "obf.vm.fcmp"));
              apply_fast_math_flags(compare, instruction.flags);
              finish_value_in_builder(helper_builder, compare);
            });
      }
      break;
    }
    case opcode::select:
      if (instruction.result_slot != invalid_slot &&
          (program.slots[instruction.result_slot].type->isIntegerTy() ||
           program.slots[instruction.result_slot].type->isPointerTy()) &&
          value_ref_type(program, instruction.operands[0])->isIntegerTy(1)) {
        auto *true_block = llvm::BasicBlock::Create(
            context, "vm.select.store.true." + std::to_string(instruction_index),
            &function);
        auto *false_block = llvm::BasicBlock::Create(
            context, "vm.select.store.false." + std::to_string(instruction_index),
            &function);
        auto *merge_block = llvm::BasicBlock::Create(
            context, "vm.select.store.merge." + std::to_string(instruction_index),
            &function);
        llvm::Value *condition = materialize_value(
            builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[0], opaque_seed, opaque_seed_base, mba_context,
            0x10000 + static_cast<std::uint64_t>(instruction_index));
        builder.CreateCondBr(condition, true_block, false_block);

        llvm::IRBuilder<> true_builder(true_block);
        llvm::Value *true_value = materialize_value(
            true_builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[1], opaque_seed, opaque_seed_base, mba_context,
            0x10100 + static_cast<std::uint64_t>(instruction_index));
        store_slot(true_builder, slot_allocas, current_slot_mapping,
                   instruction.result_slot, true_value);
        true_builder.CreateBr(merge_block);

        llvm::IRBuilder<> false_builder(false_block);
        llvm::Value *false_value = materialize_value(
            false_builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[2], opaque_seed, opaque_seed_base, mba_context,
            0x10200 + static_cast<std::uint64_t>(instruction_index));
        store_slot(false_builder, slot_allocas, current_slot_mapping,
                   instruction.result_slot, false_value);
        false_builder.CreateBr(merge_block);

        llvm::IRBuilder<> merge_builder(merge_block);
        if (instruction_index + 1 < slot_mappings.size()) {
          rotate_to_mapping(merge_builder,
                            static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value *next_target = decode_target_dispatch(
            merge_builder, layout.fallthrough_target_offset,
            0x10300 + static_cast<std::uint64_t>(instruction_index));
        emit_dispatch(merge_builder, next_target,
                      0x10400 + static_cast<std::uint64_t>(instruction_index));
      } else if (select_handler_variant(instruction.op, opaque_seed_base,
                                        0x10000 + instruction_index) == 0) {
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
      } else {
        auto *true_block = llvm::BasicBlock::Create(
            context, "vm.select.true." + std::to_string(instruction_index), &function);
        auto *false_block = llvm::BasicBlock::Create(
            context, "vm.select.false." + std::to_string(instruction_index), &function);
        auto *merge_block = llvm::BasicBlock::Create(
            context, "vm.select.merge." + std::to_string(instruction_index), &function);
        llvm::Value *condition = materialize_value(
            builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[0], opaque_seed, opaque_seed_base, mba_context,
            0x10000 + static_cast<std::uint64_t>(instruction_index));
        builder.CreateCondBr(condition, true_block, false_block);

        llvm::IRBuilder<> true_builder(true_block);
        llvm::Value *true_value = materialize_value(
            true_builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[1], opaque_seed, opaque_seed_base, mba_context,
            0x10100 + static_cast<std::uint64_t>(instruction_index));
        true_builder.CreateBr(merge_block);

        llvm::IRBuilder<> false_builder(false_block);
        llvm::Value *false_value = materialize_value(
            false_builder, slot_allocas, current_slot_mapping, program,
            instruction.operands[2], opaque_seed, opaque_seed_base, mba_context,
            0x10200 + static_cast<std::uint64_t>(instruction_index));
        false_builder.CreateBr(merge_block);

        llvm::IRBuilder<> merge_builder(merge_block);
        auto *phi =
            merge_builder.CreatePHI(true_value->getType(), 2, "obf.vm.select.phi");
        phi->addIncoming(true_value, true_block);
        phi->addIncoming(false_value, false_block);
        finish_value_in_builder(merge_builder, phi);
      }
      break;
    case opcode::load_int:
    case opcode::load_float:
    case opcode::load_ptr:
    case opcode::load_vector: {
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0x11800 + instruction_index) == 0) {
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
      } else {
        emit_in_helper_block(
            "vm.load.exec.", [&](llvm::IRBuilder<> &helper_builder) {
              auto *load = helper_builder.CreateLoad(
                  const_cast<llvm::Type *>(instruction.type),
                  materialize_value(helper_builder, slot_allocas,
                                    current_slot_mapping, program,
                                    instruction.operands[0], opaque_seed,
                                    opaque_seed_base, mba_context,
                                    0x11000 +
                                        static_cast<std::uint64_t>(instruction_index)),
                  "obf.vm.load");
              if (instruction.immediate != 0) {
                load->setAlignment(llvm::Align(instruction.immediate));
              }
              finish_value_in_builder(helper_builder, load);
            });
      }
      break;
    }
    case opcode::store_int:
    case opcode::store_float:
    case opcode::store_ptr:
    case opcode::store_vector: {
      const auto emit_store = [&](llvm::IRBuilder<> &store_builder) {
        auto *store = store_builder.CreateStore(
            materialize_value(store_builder, slot_allocas, current_slot_mapping,
                              program, instruction.operands[0], opaque_seed,
                              opaque_seed_base, mba_context,
                              0x12000 + static_cast<std::uint64_t>(instruction_index)),
            materialize_value(store_builder, slot_allocas, current_slot_mapping,
                              program, instruction.operands[1], opaque_seed,
                              opaque_seed_base, mba_context,
                              0x12100 + static_cast<std::uint64_t>(instruction_index)));
        if (instruction.immediate != 0) {
          store->setAlignment(llvm::Align(instruction.immediate));
        }
        if (instruction_index + 1 < slot_mappings.size()) {
          rotate_to_mapping(store_builder,
                            static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value *next_target = decode_target_dispatch(
            store_builder, layout.fallthrough_target_offset,
            0x12200 + static_cast<std::uint64_t>(instruction_index));
        emit_dispatch(store_builder, next_target,
                      0x12300 + static_cast<std::uint64_t>(instruction_index));
      };
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0x12800 + instruction_index) == 0) {
        emit_store(builder);
      } else {
        emit_in_helper_block("vm.store.exec.", emit_store);
      }
      break;
    }
    case opcode::extract_element: {
      finish_value(builder.CreateExtractElement(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12900 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12910 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.extract.element"));
      break;
    }
    case opcode::insert_element: {
      finish_value(builder.CreateInsertElement(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12920 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12930 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[2], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12940 + static_cast<std::uint64_t>(instruction_index)),
          "obf.vm.insert.element"));
      break;
    }
    case opcode::shuffle_vector: {
      llvm::SmallVector<int, 8> mask;
      mask.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt *mask_value : instruction.case_values) {
        mask.push_back(mask_value == nullptr ? -1
                                             : static_cast<int>(mask_value->getSExtValue()));
      }
      finish_value(builder.CreateShuffleVector(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12950 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12960 + static_cast<std::uint64_t>(instruction_index)),
          mask, "obf.vm.shuffle.vector"));
      break;
    }
    case opcode::extract_value: {
      llvm::SmallVector<unsigned, 8> indices;
      indices.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt *index_value : instruction.case_values) {
        indices.push_back(index_value == nullptr ? 0U
                                                 : static_cast<unsigned>(index_value->getZExtValue()));
      }
      finish_value(builder.CreateExtractValue(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12970 + static_cast<std::uint64_t>(instruction_index)),
          indices, "obf.vm.extract.value"));
      break;
    }
    case opcode::insert_value: {
      llvm::SmallVector<unsigned, 8> indices;
      indices.reserve(instruction.case_values.size());
      for (const llvm::ConstantInt *index_value : instruction.case_values) {
        indices.push_back(index_value == nullptr ? 0U
                                                 : static_cast<unsigned>(index_value->getZExtValue()));
      }
      finish_value(builder.CreateInsertValue(
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[0], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12980 + static_cast<std::uint64_t>(instruction_index)),
          materialize_value(builder, slot_allocas, current_slot_mapping, program,
                            instruction.operands[1], opaque_seed,
                            opaque_seed_base, mba_context,
                            0x12990 + static_cast<std::uint64_t>(instruction_index)),
          indices, "obf.vm.insert.value"));
      break;
    }
    case opcode::gep:
    case opcode::gep_inbounds: {
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
      if (instruction.op == opcode::gep_inbounds) {
        gep = builder.CreateInBoundsGEP(const_cast<llvm::Type *>(instruction.type),
                                        pointer, indices, "obf.vm.gep");
      } else {
        gep = builder.CreateGEP(const_cast<llvm::Type *>(instruction.type), pointer,
                                indices, "obf.vm.gep");
      }
      finish_value(gep);
      break;
    }
    case opcode::memmove_fixed:
    case opcode::memcpy_fixed:
    case opcode::memset_fixed: {
      const auto emit_mem = [&](llvm::IRBuilder<> &mem_builder) {
        if (instruction.op == opcode::memset_fixed) {
          (void)mem_builder.CreateMemSet(
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[0], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a00 + static_cast<std::uint64_t>(instruction_index)),
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[1], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a10 + static_cast<std::uint64_t>(instruction_index)),
              instruction.immediate, llvm::MaybeAlign());
        } else if (instruction.op == opcode::memmove_fixed) {
          (void)mem_builder.CreateMemMove(
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[0], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a20 + static_cast<std::uint64_t>(instruction_index)),
              llvm::MaybeAlign(),
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[1], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a30 + static_cast<std::uint64_t>(instruction_index)),
              llvm::MaybeAlign(), instruction.immediate);
        } else {
          (void)mem_builder.CreateMemCpy(
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[0], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a40 + static_cast<std::uint64_t>(instruction_index)),
              llvm::MaybeAlign(),
              materialize_value(mem_builder, slot_allocas, current_slot_mapping, program,
                                instruction.operands[1], opaque_seed,
                                opaque_seed_base, mba_context,
                                0x13a50 + static_cast<std::uint64_t>(instruction_index)),
              llvm::MaybeAlign(), instruction.immediate);
        }
        if (instruction_index + 1 < slot_mappings.size()) {
          rotate_to_mapping(mem_builder,
                            static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value *next_target = decode_target_dispatch(
            mem_builder, layout.fallthrough_target_offset,
            0x13a60 + static_cast<std::uint64_t>(instruction_index));
        emit_dispatch(mem_builder, next_target,
                      0x13a70 + static_cast<std::uint64_t>(instruction_index));
      };
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0x13a80 + instruction_index) == 0) {
        emit_mem(builder);
      } else {
        emit_in_helper_block("vm.mem.exec.", emit_mem);
      }
      break;
    }
    case opcode::call: {
      const auto emit_call = [&](llvm::IRBuilder<> &call_builder) {
        llvm::SmallVector<llvm::Value *, 8> arguments;
        arguments.reserve(instruction.operands.size() - 1);
        for (std::size_t operand_index = 1;
             operand_index < instruction.operands.size(); ++operand_index) {
          arguments.push_back(materialize_value(
              call_builder, slot_allocas, current_slot_mapping, program,
              instruction.operands[operand_index], opaque_seed, opaque_seed_base,
              mba_context,
              0x14000 + static_cast<std::uint64_t>(instruction_index) * 16 +
                  operand_index));
        }

        auto *call = call_builder.CreateCall(
            llvm::cast<llvm::FunctionType>(const_cast<llvm::Type *>(instruction.type)),
            materialize_value(call_builder, slot_allocas, current_slot_mapping,
                              program, instruction.operands[0], opaque_seed,
                              opaque_seed_base, mba_context,
                              0x14100 + static_cast<std::uint64_t>(instruction_index)),
            arguments,
            instruction.result_slot == invalid_slot ? "" : "obf.vm.call");
        call->setCallingConv(
            static_cast<llvm::CallingConv::ID>(instruction.subtype));
        call->setAttributes(instruction.attributes);
        apply_fast_math_flags(call, instruction.flags);
        if (instruction.result_slot != invalid_slot) {
          store_slot(call_builder, slot_allocas, current_slot_mapping,
                     instruction.result_slot, call);
        }
        if (instruction_index + 1 < slot_mappings.size()) {
          rotate_to_mapping(call_builder,
                            static_cast<std::uint32_t>(instruction_index + 1));
        }
        llvm::Value *next_target = decode_target_dispatch(
            call_builder, layout.fallthrough_target_offset,
            0x14200 + static_cast<std::uint64_t>(instruction_index));
        emit_dispatch(call_builder, next_target,
                      0x14300 + static_cast<std::uint64_t>(instruction_index));
      };
      if (select_handler_variant(instruction.op, opaque_seed_base,
                                 0x14800 + instruction_index) == 0) {
        emit_call(builder);
      } else {
        emit_in_helper_block("vm.call.exec.", emit_call);
      }
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
        //   encoded = ret_val ^ cast(retkey ^ hidden_token ^ (state ^ expected_state))
        // Under normal (untampered) execution state == expected_state, so the
        // poison term cancels and the caller sees ret_val ^ cast(retkey ^ hidden_token).
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
          llvm::Value *token_component = hidden_token_arg != nullptr
                                             ? static_cast<llvm::Value *>(hidden_token_arg)
                                             : builder.getInt64(opaque_seed_base);
          if (token_component->getType() != builder.getInt64Ty()) {
            token_component = builder.CreateZExtOrTrunc(
                token_component, builder.getInt64Ty(), "obf.vm.ret.token.cast");
          }
          llvm::Value *token_key = mba::create_xor(
              builder, retkey_load, token_component, mba_context,
              ret_salt + 2, "obf.vm.ret.tokenkey");
          llvm::Value *full_key = mba::create_xor(
              builder, token_key, poison, mba_context,
              ret_salt + 3, "obf.vm.ret.fullkey");
          llvm::Value *key_trunc = full_key;
          if (ret_val->getType() != builder.getInt64Ty()) {
            key_trunc = builder.CreateZExtOrTrunc(
                full_key, ret_val->getType(), "obf.vm.ret.key.cast");
          }
          ret_val = mba::create_xor(
              builder, ret_val, key_trunc, mba_context,
              ret_salt + 4, "obf.vm.ret.encoded");
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
