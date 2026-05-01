#pragma once

#include "llvm/IR/Attributes.h"

#include <cstdint>
#include <limits>
#include <vector>

namespace llvm {
class Constant;
class ConstantInt;
class Type;
}  // namespace llvm

namespace obf::vm {

inline constexpr std::uint32_t invalid_slot = std::numeric_limits<std::uint32_t>::max();

enum class slot_kind : std::uint8_t {
  integer,
  floating,
  pointer,
  vector,
  aggregate,
};

struct slot_desc {
  const llvm::Type* type = nullptr;
  slot_kind kind = slot_kind::integer;
};

enum class value_ref_kind : std::uint8_t {
  slot,
  constant,
};

struct value_ref {
  value_ref_kind kind = value_ref_kind::slot;
  std::uint32_t slot = invalid_slot;
  const llvm::Constant* constant = nullptr;
};

enum class opcode : std::uint8_t {
  add,
  sub,
  mul,
  udiv,
  sdiv,
  urem,
  srem,
  shl,
  lshr,
  ashr,
  and_op,
  or_op,
  xor_op,
  fadd,
  fsub,
  fmul,
  fdiv,
  frem,
  trunc,
  zext,
  sext,
  fp_trunc,
  fp_ext,
  ui_to_fp,
  si_to_fp,
  fp_to_ui,
  fp_to_si,
  ptr_to_int,
  int_to_ptr,
  bitcast,
  addrspace_cast,
  fneg,
  freeze,
  icmp_eq,
  icmp_ne,
  icmp_ugt,
  icmp_uge,
  icmp_ult,
  icmp_ule,
  icmp_sgt,
  icmp_sge,
  icmp_slt,
  icmp_sle,
  fcmp_false,
  fcmp_oeq,
  fcmp_ogt,
  fcmp_oge,
  fcmp_olt,
  fcmp_ole,
  fcmp_one,
  fcmp_ord,
  fcmp_uno,
  fcmp_ueq,
  fcmp_ugt,
  fcmp_uge,
  fcmp_ult,
  fcmp_ule,
  fcmp_une,
  fcmp_true,
  select,
  load_int,
  load_float,
  load_ptr,
  load_vector,
  store_int,
  store_float,
  store_ptr,
  store_vector,
  extract_element,
  insert_element,
  shuffle_vector,
  extract_value,
  insert_value,
  gep,
  gep_inbounds,
  memmove_fixed,
  memcpy_fixed,
  memset_fixed,
  call,
  jump,
  branch,
  switch_op,
  unreachable_op,
  ret,
};

inline constexpr std::uint32_t instruction_flag_nsw = 1U << 0;
inline constexpr std::uint32_t instruction_flag_nuw = 1U << 1;
inline constexpr std::uint32_t instruction_flag_exact = 1U << 2;
inline constexpr std::uint32_t instruction_flag_fast_reassoc = 1U << 8;
inline constexpr std::uint32_t instruction_flag_fast_nnan = 1U << 9;
inline constexpr std::uint32_t instruction_flag_fast_ninf = 1U << 10;
inline constexpr std::uint32_t instruction_flag_fast_nsz = 1U << 11;
inline constexpr std::uint32_t instruction_flag_fast_arcp = 1U << 12;
inline constexpr std::uint32_t instruction_flag_fast_contract = 1U << 13;
inline constexpr std::uint32_t instruction_flag_fast_afn = 1U << 14;
inline constexpr std::uint32_t instruction_flag_fast_fast = 1U << 15;

inline constexpr bool has_instruction_flag(std::uint32_t flags, std::uint32_t bit) {
  return (flags & bit) != 0;
}

struct edge_assignment {
  std::uint32_t slot = invalid_slot;
  value_ref value;
};

struct control_edge {
  std::uint32_t target_block = 0;
  std::vector<edge_assignment> assignments;
};

struct basic_block_desc {
  std::uint32_t first_instruction = 0;
};

struct micro_instruction {
  opcode op = opcode::ret;
  std::uint32_t result_slot = invalid_slot;
  std::uint32_t subtype = 0;
  std::uint32_t flags = 0;
  std::uint32_t immediate = 0;
  const llvm::Type* type = nullptr;
  llvm::AttributeList attributes;
  std::vector<value_ref> operands;
  std::vector<control_edge> edges;
  std::vector<const llvm::ConstantInt*> case_values;
};

struct bytecode_program {
  std::vector<slot_desc> slots;
  std::vector<std::uint32_t> argument_slots;
  std::vector<basic_block_desc> blocks;
  std::vector<micro_instruction> instructions;
};

}  // namespace obf::vm
