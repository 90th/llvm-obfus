#pragma once

#include "obf/vm/vm_types.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"

#include <array>
#include <cstdint>
#include <vector>

namespace obf::vm {

// Opcode permutation for dispatcher polymorphism
struct opcode_permutation {
  std::array<std::uint8_t, vm_opcode_count> physical_for_logical = {};
};

// Header chunk metadata
struct bytecode_header_chunk {
  std::uint32_t offset = 0;
  std::uint8_t size = 0;
  bool carries_opcode = false;
};

// Pending header chunk during construction
struct pending_bytecode_header_chunk {
  std::array<std::uint8_t, 4> decoded_bytes = {};
  std::uint64_t order_key = 0;
  std::uint8_t size = 0;
  bool carries_opcode = false;
};

// Bytecode layout for a single instruction
struct bytecode_layout {
  std::uint32_t header_offset = 0;
  std::vector<bytecode_header_chunk> header_chunks;
  std::uint32_t fallthrough_target_offset = invalid_slot;
  std::vector<std::uint32_t> edge_target_offsets;
  std::uint32_t integrity_probe_range = 0;
  std::uint64_t expected_post_header_state = 0;
};

// Complete serialized bytecode program
struct serialized_bytecode_program {
  std::vector<std::uint8_t> bytes;
  std::vector<bytecode_layout> layouts;
};

// Switch dispatch bank for split dispatchers
struct switch_dispatch_bank {
  llvm::BasicBlock* block = nullptr;
  llvm::PHINode* dispatch_index_phi = nullptr;
  llvm::SwitchInst* switch_inst = nullptr;
  std::uint64_t salt = 0;
};

// VM runtime state struct layout
struct vm_state_layout {
  llvm::StructType* type = nullptr;
  std::uint32_t bytecode_state_field = 0;
  std::uint32_t dispatch_index_field = 1;
  std::uint32_t island_id_field = 2;
  std::uint32_t hidden_token_field = 3;
  std::uint32_t return_value_field = invalid_slot;
  std::vector<std::array<std::uint32_t, vm_slot_rotation_cell_count>> slot_fields;
};

}  // namespace obf::vm
