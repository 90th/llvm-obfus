#pragma once

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"
#include "obf/vm/micro_ir.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/ErrorHandling.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace obf::vm {

using slot_cells = llvm::SmallVector<llvm::Value *, 4>;
using slot_storage = llvm::SmallVector<slot_cells, 16>;
using slot_cell_mapping = std::vector<std::uint32_t>;

inline constexpr std::uint32_t vm_slot_rotation_cell_count = 3;
inline constexpr std::size_t vm_opcode_count =
    static_cast<std::size_t>(opcode::ret) + 1;
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

enum class dispatch_backend_variant : std::uint32_t {
  switch_index = 0,
  direct_threaded_match = 1,
  direct_threaded_switch = 2,
};

enum class vm_dispatcher_shape : std::uint32_t {
  direct_threaded = 0,
  switch_biased = 1,
  banked = 2,
};

enum class vm_island_topology : std::uint32_t {
  none = 0,
  helper_shards = 1,
};

enum class scalar_handler_shape : std::uint32_t {
  direct = 0,
  temp_slot_roundtrip = 1,
  mba_neutralized = 2,
};

enum class compare_handler_shape : std::uint32_t {
  direct = 0,
  bool_xor_neutralized = 1,
  inverted_predicate = 2,
  select_materialized = 3,
};

enum class branch_handler_shape : std::uint32_t {
  direct = 0,
  inverted_condition_swap = 1,
  neutralized_condition = 2,
  select_condition = 3,
};

enum class memory_handler_shape : std::uint32_t {
  direct = 0,
  pointer_roundtrip = 1,
  offset_neutralized = 2,
  addr_select_neutralized = 3,
  value_slot_roundtrip = 4,
};

enum class gep_handler_shape : std::uint32_t {
  direct = 0,
  split_index_add = 1,
  ptrint_roundtrip = 2,
  offset_bias = 3,
  select_equivalent_base = 4,
};

enum class call_handler_shape : std::uint32_t {
  direct = 0,
  argument_shuffle_roundtrip = 1,
  token_guarded_call = 2,
  result_slot_roundtrip = 3,
};

enum class return_handler_shape : std::uint32_t {
  direct = 0,
  result_slot_roundtrip = 1,
  neutralized_encode = 2,
  split_encode = 3,
};

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

struct opcode_permutation {
  std::array<std::uint8_t, vm_opcode_count> physical_for_logical = {};
};

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

struct switch_dispatch_bank {
  llvm::BasicBlock *block = nullptr;
  llvm::PHINode *dispatch_index_phi = nullptr;
  llvm::SwitchInst *switch_inst = nullptr;
  std::uint64_t salt = 0;
};

struct vm_state_layout {
  llvm::StructType *type = nullptr;
  std::uint32_t bytecode_state_field = 0;
  std::uint32_t dispatch_index_field = 1;
  std::uint32_t island_id_field = 2;
  std::uint32_t hidden_token_field = 3;
  std::uint32_t return_value_field = invalid_slot;
  std::vector<std::array<std::uint32_t, vm_slot_rotation_cell_count>> slot_fields;
};

struct rewrite_function_context {
  llvm::Function &function;
  const bytecode_program &program;
  const slot_storage &slot_allocas;
  const std::vector<slot_cell_mapping> &slot_mappings;
  llvm::AllocaInst *opaque_seed_slot = nullptr;
  std::uint64_t opaque_seed_base = 0;
  const mba::builder_context &mba_context;
  llvm::Argument *hidden_token_arg = nullptr;
  std::uint64_t bytecode_seed = 0;
  const opcode_permutation &opcode_map;
  dispatch_backend_variant dispatch_backend =
      dispatch_backend_variant::switch_index;
  vm_dispatcher_shape dispatch_shape = vm_dispatcher_shape::switch_biased;
  vm_island_topology island_topology = vm_island_topology::none;
  std::uint32_t island_count = 0;
  std::uint32_t switch_dispatch_bank_count = 1;
  llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction;
  llvm::GlobalVariable *bytecode_global = nullptr;
  llvm::GlobalVariable *retkey_global = nullptr;
  const vm_state_layout *state_layout = nullptr;
  llvm::Value *state_storage = nullptr;
  llvm::Value *state_slot = nullptr;
  llvm::Value *dispatch_index_slot = nullptr;
  llvm::Value *island_id_slot = nullptr;
  llvm::Value *hidden_token_slot = nullptr;
  llvm::Value *return_value_slot = nullptr;
  llvm::BasicBlock *trap_block = nullptr;
  llvm::ArrayRef<llvm::BasicBlock *> instruction_blocks;
  llvm::ArrayRef<std::uint32_t> island_for_instruction;
  bool state_island_body = false;
  llvm::BasicBlock *island_route_block = nullptr;
  llvm::PHINode *island_route_phi = nullptr;
  llvm::AllocaInst *dispatch_table = nullptr;
  llvm::ArrayType *dispatch_table_type = nullptr;
  llvm::IntegerType *ptr_int_type = nullptr;
  std::vector<switch_dispatch_bank> &switch_dispatch_banks;
  std::size_t &dispatch_site_counter;
};

struct instruction_rewrite_context {
  rewrite_function_context &function_context;
  std::size_t instruction_index = 0;
  const micro_instruction &instruction;
  const bytecode_layout &layout;
  llvm::ArrayRef<std::uint32_t> current_slot_mapping;
};

inline std::size_t opcode_to_index(opcode op) {
  return static_cast<std::size_t>(op);
}

inline std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  return obf::mix_seed(seed, salt);
}

std::uint64_t derive_vm_bytecode_seed(const llvm::Function &function,
                                      const bytecode_program &program);

llvm::FastMathFlags decode_fast_math_flags(std::uint32_t flags);
void apply_fast_math_flags(llvm::Instruction *instruction, std::uint32_t flags);

std::uint32_t select_handler_variant(opcode op, std::uint64_t seed_base,
                                     std::uint64_t salt,
                                     std::uint32_t variant_count = 2);
scalar_handler_shape select_scalar_handler_shape(std::uint64_t seed_base,
                                                 opcode op,
                                                 std::uint8_t physical_opcode,
                                                 std::uint64_t salt);
compare_handler_shape select_compare_handler_shape(
    const rewrite_function_context &context,
    const micro_instruction &instruction,
    std::size_t instruction_index, std::uint64_t salt);
branch_handler_shape select_branch_handler_shape(
    const rewrite_function_context &context,
    const micro_instruction &instruction,
    std::size_t instruction_index, std::uint64_t salt);
memory_handler_shape select_memory_handler_shape(
    const rewrite_function_context &context,
    const micro_instruction &instruction,
    std::size_t instruction_index, std::uint64_t salt);
gep_handler_shape select_gep_handler_shape(const rewrite_function_context &context,
                                           const micro_instruction &instruction,
                                           std::size_t instruction_index,
                                           std::uint64_t salt);
call_handler_shape select_call_handler_shape(
    const rewrite_function_context &context,
    const micro_instruction &instruction,
    std::size_t instruction_index, std::uint64_t salt);
return_handler_shape select_return_handler_shape(
    const rewrite_function_context &context,
    const micro_instruction &instruction,
    std::size_t instruction_index, std::uint64_t salt);
vm_status_choreography_shape select_status_choreography_shape(
    const llvm::Function &function, std::uint64_t bytecode_seed,
    std::uint32_t detail, std::uint64_t salt);
vm_next_route_choreography_shape select_next_route_choreography_shape(
    const rewrite_function_context &context, std::uint32_t target_instruction,
    std::uint64_t salt);
vm_slot_update_choreography_shape select_slot_update_choreography_shape(
    const rewrite_function_context &context, std::uint32_t slot,
    std::uint64_t salt);
vm_table_access_choreography_shape select_table_access_choreography_shape(
    const rewrite_function_context &context, std::uint32_t table_index,
    std::uint64_t salt);
vm_helper_dispatch_choreography_shape select_helper_dispatch_choreography_shape(
    const llvm::Function &function, std::uint64_t bytecode_seed,
    std::size_t dispatch_case_count, std::uint64_t salt);

std::uint32_t select_dispatch_variant(std::uint64_t seed_base, std::uint64_t salt,
                                      std::size_t instruction_count,
                                      std::uint32_t variant_count = 3);
vm_dispatcher_shape select_dispatcher_shape(std::uint64_t seed_base,
                                            std::uint64_t salt,
                                            std::size_t instruction_count);
std::uint32_t select_switch_dispatch_bank_count(std::uint64_t seed_base,
                                                std::uint64_t salt,
                                                std::size_t instruction_count,
                                                vm_dispatcher_shape shape);
vm_island_topology select_vm_island_topology(bool prefer_islands,
                                             std::size_t instruction_count,
                                             std::uint64_t seed_base,
                                             std::uint64_t salt);
std::uint32_t select_vm_island_count(std::uint64_t seed_base,
                                     std::uint64_t salt,
                                     std::size_t instruction_count,
                                     vm_island_topology topology);
opcode_permutation build_opcode_permutation(const llvm::Function &function,
                                            const bytecode_program &program);
std::uint8_t get_physical_opcode(const opcode_permutation &permutation,
                                 opcode logical_opcode);
std::vector<slot_cell_mapping>
build_slot_cell_mappings(const bytecode_program &program, std::uint64_t seed_base);
std::vector<std::uint32_t>
build_dispatch_index_map(const bytecode_program &program, std::uint64_t seed,
                         dispatch_backend_variant dispatch_backend);
std::vector<std::uint64_t>
build_instruction_entry_states(const bytecode_program &program,
                               std::uint64_t seed);
void initialize_dispatch_runtime(llvm::IRBuilder<> &entry_builder,
                                 rewrite_function_context &context);
void emit_dispatch(llvm::IRBuilder<> &builder,
                    rewrite_function_context &context,
                    llvm::Value *dispatch_index, std::uint64_t salt,
                    std::uint32_t target_instruction = invalid_slot);
std::uint32_t outline_vm_islands(rewrite_function_context &context);

serialized_bytecode_program serialize_bytecode_program(
    const bytecode_program &program,
    llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
    llvm::ArrayRef<std::uint64_t> entry_states, std::uint64_t seed_base,
    const opcode_permutation &opcode_map);
llvm::Value *consume_metadata(llvm::IRBuilder<> &builder,
                              const rewrite_function_context &context,
                              const bytecode_layout &layout,
                              std::uint64_t salt);
llvm::Value *decode_target_dispatch(llvm::IRBuilder<> &builder,
                                    const rewrite_function_context &context,
                                    std::uint32_t offset, std::uint64_t salt);
void emit_instruction_integrity_probes(llvm::IRBuilder<> &builder,
                                       const instruction_rewrite_context &context);

llvm::Value *load_slot(llvm::IRBuilder<> &builder,
                       const slot_storage &slot_allocas,
                       llvm::ArrayRef<std::uint32_t> slot_mapping,
                       const bytecode_program &program, std::uint32_t slot,
                       const mba::builder_context &mba_context,
                       std::uint64_t salt);
void store_slot(llvm::IRBuilder<> &builder,
                const slot_storage &slot_allocas,
                llvm::ArrayRef<std::uint32_t> slot_mapping,
                const bytecode_program &program, std::uint32_t slot,
                llvm::Value *value, llvm::AllocaInst *opaque_seed_slot,
                std::uint64_t opaque_seed_base,
                const mba::builder_context &mba_context, std::uint64_t salt);
void rotate_slot_cells(llvm::IRBuilder<> &builder, const slot_storage &slot_allocas,
                       const bytecode_program &program,
                       llvm::ArrayRef<std::uint32_t> current_mapping,
                       llvm::ArrayRef<std::uint32_t> target_mapping,
                       const mba::builder_context &mba_context,
                       std::uint64_t salt);

llvm::Value *materialize_integer_constant(llvm::IRBuilder<> &builder,
                                          const llvm::ConstantInt &integer,
                                          llvm::AllocaInst *opaque_seed_slot,
                                          std::uint64_t opaque_seed_base,
                                          const mba::builder_context &mba_context,
                                          std::uint64_t salt);
const llvm::DataLayout *get_builder_data_layout(const llvm::IRBuilder<> &builder);
llvm::IntegerType *get_pointer_carrier_type(llvm::IRBuilder<> &builder,
                                            llvm::Type *type);
llvm::Value *materialize_pointer_carrier(
    llvm::IRBuilder<> &builder, llvm::Value *pointer_value,
    llvm::AllocaInst *opaque_seed_slot, std::uint64_t opaque_seed_base,
    const mba::builder_context &mba_context, std::uint64_t salt);
llvm::Value *materialize_pointer_value(llvm::IRBuilder<> &builder,
                                       llvm::Value *pointer_value,
                                       llvm::AllocaInst *opaque_seed_slot,
                                       std::uint64_t opaque_seed_base,
                                       const mba::builder_context &mba_context,
                                       std::uint64_t salt);
llvm::Value *materialize_value(llvm::IRBuilder<> &builder,
                               const slot_storage &slot_allocas,
                               llvm::ArrayRef<std::uint32_t> slot_mapping,
                               const bytecode_program &program,
                               const value_ref &value,
                               llvm::AllocaInst *opaque_seed_slot,
                               std::uint64_t opaque_seed_base,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt);
const llvm::Type *value_ref_type(const bytecode_program &program,
                                 const value_ref &value);
llvm::Value *materialize_pointer_carrier_from_value_ref(
    llvm::IRBuilder<> &builder, const slot_storage &slot_allocas,
    llvm::ArrayRef<std::uint32_t> slot_mapping, const bytecode_program &program,
    const value_ref &value, llvm::AllocaInst *opaque_seed_slot,
    std::uint64_t opaque_seed_base, const mba::builder_context &mba_context,
    std::uint64_t salt);
llvm::Value *load_pointer_carrier_from_memory(
    llvm::IRBuilder<> &builder, llvm::Value *address, llvm::Type *pointer_type,
    const mba::builder_context &mba_context, std::uint64_t salt,
    llvm::MaybeAlign alignment = llvm::MaybeAlign(),
    llvm::StringRef name_prefix = "obf.vm.ptr.load");
llvm::Value *load_pointer_value_from_memory(
    llvm::IRBuilder<> &builder, llvm::Value *address, llvm::Type *pointer_type,
    const mba::builder_context &mba_context, std::uint64_t salt,
    llvm::MaybeAlign alignment = llvm::MaybeAlign(),
    llvm::StringRef name_prefix = "obf.vm.ptr.load");
llvm::StoreInst *store_pointer_carrier_to_memory(
    llvm::IRBuilder<> &builder, llvm::Value *address, llvm::Value *carrier,
    llvm::Type *pointer_type, const mba::builder_context &mba_context,
    std::uint64_t salt, llvm::MaybeAlign alignment = llvm::MaybeAlign());
llvm::StoreInst *store_pointer_value_to_memory(
    llvm::IRBuilder<> &builder, llvm::Value *address, llvm::Value *pointer_value,
    llvm::Type *pointer_type, llvm::AllocaInst *opaque_seed_slot,
    std::uint64_t opaque_seed_base, const mba::builder_context &mba_context,
    std::uint64_t salt, llvm::MaybeAlign alignment = llvm::MaybeAlign());

llvm::Value *emit_unsigned_integer_width_cast(
    llvm::IRBuilder<> &builder, llvm::Value *operand,
    llvm::IntegerType *destination_type,
    const mba::builder_context &mba_context, std::uint64_t salt);
bool lower_scalar_instruction(llvm::IRBuilder<> &builder,
                              const instruction_rewrite_context &context);
bool lower_memory_instruction(llvm::IRBuilder<> &builder,
                              const instruction_rewrite_context &context);

void apply_edge_assignments(llvm::IRBuilder<> &builder,
                            const instruction_rewrite_context &context,
                            const control_edge &edge, std::uint64_t salt);
void rotate_to_mapping(llvm::IRBuilder<> &builder,
                       const instruction_rewrite_context &context,
                       std::uint32_t target_instruction);
void finish_value_in_builder(llvm::IRBuilder<> &builder,
                             const instruction_rewrite_context &context,
                             llvm::Value *result);
bool lower_control_instruction(llvm::IRBuilder<> &builder,
                               const instruction_rewrite_context &context);
llvm::Value *apply_vm_island_status_choreography(
    llvm::IRBuilder<> &builder, llvm::Function &function,
    std::uint64_t bytecode_seed, llvm::Value *status_value,
    std::uint32_t detail, std::uint64_t salt);
llvm::Value *apply_vm_helper_dispatch_choreography(
    llvm::IRBuilder<> &builder, llvm::Function &function,
    std::uint64_t bytecode_seed, llvm::Value *dispatch_value,
    std::size_t dispatch_case_count, std::uint64_t salt);

inline void finish_value(llvm::IRBuilder<> &builder,
                         const instruction_rewrite_context &context,
                         llvm::Value *result) {
  finish_value_in_builder(builder, context, result);
}

inline llvm::AllocaInst *create_vm_handler_temp_slot(llvm::IRBuilder<> &builder,
                                                     llvm::Type *type,
                                                     const llvm::Twine &name) {
  llvm::BasicBlock *block = builder.GetInsertBlock();
  llvm::Function *function = block != nullptr ? block->getParent() : nullptr;
  if (function == nullptr || type == nullptr || !type->isSized()) {
    return nullptr;
  }

  llvm::BasicBlock &entry_block = function->getEntryBlock();
  llvm::IRBuilder<> entry_builder(&entry_block, entry_block.begin());
  return entry_builder.CreateAlloca(type, nullptr, name);
}

inline llvm::Value *roundtrip_vm_handler_value(llvm::IRBuilder<> &builder,
                                               llvm::Value *value,
                                               const llvm::Twine &name) {
  if (value == nullptr || value->getType()->isVoidTy() ||
      !value->getType()->isSized()) {
    return value;
  }

  llvm::AllocaInst *temp =
      create_vm_handler_temp_slot(builder, value->getType(), name + ".slot");
  if (temp == nullptr) {
    return value;
  }

  builder.CreateStore(value, temp);
  return builder.CreateLoad(value->getType(), temp, name);
}

inline llvm::Value *tag_vm_handler_value(llvm::Value *value,
                                         llvm::StringRef marker) {
  if (value == nullptr || llvm::isa<llvm::Constant>(value)) {
    return value;
  }

  value->setName(marker);
  return value;
}

template <typename EmitFn>
void emit_in_helper_block(llvm::IRBuilder<> &builder,
                          const instruction_rewrite_context &context,
                          llvm::StringRef name, EmitFn &&emit) {
  auto *helper_block = llvm::BasicBlock::Create(
      context.function_context.function.getContext(),
      (name + std::to_string(context.instruction_index)).str(),
      &context.function_context.function);
  builder.CreateBr(helper_block);
  llvm::IRBuilder<> helper_builder(helper_block);
  emit(helper_builder);
}

} // namespace obf::vm
