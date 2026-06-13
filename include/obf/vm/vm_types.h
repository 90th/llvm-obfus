#pragma once

#include "obf/vm/micro_ir.h"

#include <cstddef>
#include <cstdint>

namespace obf::vm {

// VM configuration constants
inline constexpr std::uint32_t vm_slot_rotation_cell_count = 3;
inline constexpr std::size_t vm_opcode_count = static_cast<std::size_t>(opcode::ret) + 1;
inline constexpr std::size_t vm_switch_dispatch_min_instruction_count = 16;
inline constexpr std::size_t vm_island_min_instruction_count = 16;
inline constexpr std::size_t vm_island_max_count = 6;
inline constexpr std::size_t vm_subisland_min_instruction_count = 4;
inline constexpr std::size_t vm_subisland_target_instruction_count = 10;
inline constexpr std::size_t vm_subisland_max_count = 8;
inline constexpr std::size_t switch_dispatch_max_bank_count = 4;
inline constexpr std::uint32_t vm_island_continue_status = 0xfffffffdU;
inline constexpr std::uint32_t vm_island_done_status = 0xfffffffeU;
inline constexpr std::uint32_t vm_island_trap_status = 0xffffffffU;

// Dispatch backend selection
enum class dispatch_backend_variant : std::uint32_t {
  switch_index = 0,
  direct_threaded_match = 1,
  direct_threaded_switch = 2,
};

// Dispatcher shape polymorphism
enum class vm_dispatcher_shape : std::uint32_t {
  direct_threaded = 0,
  switch_biased = 1,
  banked = 2,
};

// VM island topology
enum class vm_island_topology : std::uint32_t {
  none = 0,
  helper_shards = 1,
};

// Handler shape polymorphism - scalar operations
enum class scalar_handler_shape : std::uint32_t {
  direct = 0,
  temp_slot_roundtrip = 1,
  mba_neutralized = 2,
};

// Handler shape polymorphism - comparisons
enum class compare_handler_shape : std::uint32_t {
  direct = 0,
  bool_xor_neutralized = 1,
  inverted_predicate = 2,
  select_materialized = 3,
};

// Handler shape polymorphism - branches
enum class branch_handler_shape : std::uint32_t {
  direct = 0,
  inverted_condition_swap = 1,
  neutralized_condition = 2,
  select_condition = 3,
};

// Handler shape polymorphism - memory operations
enum class memory_handler_shape : std::uint32_t {
  direct = 0,
  pointer_roundtrip = 1,
  offset_neutralized = 2,
  addr_select_neutralized = 3,
  value_slot_roundtrip = 4,
};

// Handler shape polymorphism - GEP instructions
enum class gep_handler_shape : std::uint32_t {
  direct = 0,
  split_index_add = 1,
  ptrint_roundtrip = 2,
  offset_bias = 3,
  select_equivalent_base = 4,
};

// Handler shape polymorphism - function calls
enum class call_handler_shape : std::uint32_t {
  direct = 0,
  argument_shuffle_roundtrip = 1,
  token_guarded_call = 2,
  result_slot_roundtrip = 3,
};

// Handler shape polymorphism - return instructions
enum class return_handler_shape : std::uint32_t {
  direct = 0,
  result_slot_roundtrip = 1,
  neutralized_encode = 2,
  split_encode = 3,
};

// Choreography shapes for VM state transitions
enum class vm_status_choreography_shape : std::uint32_t {
  direct = 0,
  temp = 1,
  split = 2,
  select = 3,
};

enum class vm_next_route_choreography_shape : std::uint32_t {
  direct = 0,
  dispatch_index_temp = 1,
  island_id_temp = 2,
  packed_pair = 3,
  temp_pair = 4,
};

enum class vm_slot_update_choreography_shape : std::uint32_t {
  direct = 0,
  temp = 1,
  rotate = 2,
  select = 3,
  split = 4,
};

enum class vm_table_access_choreography_shape : std::uint32_t {
  direct = 0,
  temp = 1,
  bias = 2,
  split = 3,
  select = 4,
};

enum class vm_helper_dispatch_choreography_shape : std::uint32_t {
  direct = 0,
  bias = 1,
  split = 2,
  select = 3,
};

// Utility: convert opcode to array index
inline std::size_t opcode_to_index(opcode op) { return static_cast<std::size_t>(op); }

}  // namespace obf::vm
