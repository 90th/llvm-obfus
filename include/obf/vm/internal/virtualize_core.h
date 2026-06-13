#ifndef OBF_VM_INTERNAL_VIRTUALIZE_CORE_H
#define OBF_VM_INTERNAL_VIRTUALIZE_CORE_H

#include "obf/transforms/mba.h"
#include "obf/vm/micro_ir.h"
#include "obf/vm/virtualize.h"
#include "obf/vm/vm_layout.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Value.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace obf::vm {

using slot_cells = llvm::SmallVector<llvm::Value*, 4>;
using slot_storage = llvm::SmallVector<slot_cells, 16>;
using slot_cell_mapping = std::vector<std::uint32_t>;

struct rewrite_function_context {
  llvm::Function& function;
  const bytecode_program& program;
  const slot_storage& slot_allocas;
  const std::vector<slot_cell_mapping>& slot_mappings;
  llvm::AllocaInst* opaque_seed_slot = nullptr;
  std::uint64_t opaque_seed_base = 0;
  const mba::builder_context& mba_context;
  llvm::Argument* hidden_token_arg = nullptr;
  std::uint64_t bytecode_seed = 0;
  const opcode_permutation& opcode_map;
  dispatch_backend_variant dispatch_backend = dispatch_backend_variant::switch_index;
  vm_dispatcher_shape dispatch_shape = vm_dispatcher_shape::switch_biased;
  vm_island_topology island_topology = vm_island_topology::none;
  std::uint32_t island_count = 0;
  std::uint32_t switch_dispatch_bank_count = 1;
  llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction;
  llvm::GlobalVariable* bytecode_global = nullptr;
  llvm::ArrayRef<llvm::GlobalVariable*> bytecode_anchor_globals;
  std::uint32_t bytecode_anchor_real_count = 0;
  std::uint32_t bytecode_anchor_decoy_count = 0;
  llvm::GlobalVariable* retkey_global = nullptr;
  const vm_state_layout* state_layout = nullptr;
  llvm::Value* state_storage = nullptr;
  llvm::Value* state_slot = nullptr;
  llvm::Value* dispatch_index_slot = nullptr;
  llvm::Value* island_id_slot = nullptr;
  llvm::Value* hidden_token_slot = nullptr;
  llvm::Value* return_value_slot = nullptr;
  llvm::BasicBlock* trap_block = nullptr;
  llvm::Value* opcode_predicate_slot = nullptr;
  llvm::ArrayRef<llvm::BasicBlock*> instruction_blocks;
  llvm::ArrayRef<std::uint32_t> island_for_instruction;
  bool state_island_body = false;
  llvm::BasicBlock* island_route_block = nullptr;
  llvm::PHINode* island_route_phi = nullptr;
  llvm::AllocaInst* dispatch_table = nullptr;
  llvm::ArrayType* dispatch_table_type = nullptr;
  llvm::IntegerType* ptr_int_type = nullptr;
  std::vector<switch_dispatch_bank>& switch_dispatch_banks;
  std::size_t& dispatch_site_counter;
};

struct instruction_rewrite_context {
  rewrite_function_context& function_context;
  std::size_t instruction_index = 0;
  const micro_instruction& instruction;
  const bytecode_layout& layout;
  llvm::ArrayRef<std::uint32_t> current_slot_mapping;
};

struct VmDecoyRoutePlan {
  std::uint32_t real_instruction = invalid_slot;
  std::uint32_t decoy_instruction = invalid_slot;
  std::uint32_t real_dispatch_index = invalid_slot;
  std::uint32_t decoy_dispatch_index = invalid_slot;
  std::uint32_t real_island = invalid_slot;
  std::uint32_t decoy_island = invalid_slot;
  std::uint32_t decoy_slot = invalid_slot;
  std::uint64_t salt = 0;
};

}  // namespace obf::vm

#endif
