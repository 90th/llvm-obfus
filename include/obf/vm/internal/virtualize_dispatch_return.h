#ifndef OBF_VM_INTERNAL_VIRTUALIZE_DISPATCH_RETURN_H
#define OBF_VM_INTERNAL_VIRTUALIZE_DISPATCH_RETURN_H

#include "obf/vm/internal/virtualize_core.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"

#include <cstddef>
#include <cstdint>

namespace obf::vm {

struct bytecode_program;
struct serialized_bytecode_program;
struct subisland_plan;
struct virtualization_options;

enum class vm_body_layout_shape {
  logical = 0,
  permuted = 1,
  family = 2,
};

enum class vm_status_trap_shape {
  direct = 0,
  twohop = 1,
  slot = 2,
};

enum class vm_terminal_trap_shape {
  direct = 0,
  twohop = 1,
  gated = 2,
};

vm_body_layout_shape select_vm_body_layout_shape(const llvm::Function& function,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t detail,
                                                 std::size_t instruction_count);

vm_status_trap_shape select_vm_status_trap_shape(const llvm::Function& function,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t detail);

vm_terminal_trap_shape select_vm_terminal_trap_shape(const llvm::Function& function,
                                                     std::uint64_t bytecode_seed,
                                                     std::uint64_t detail);

llvm::StringRef vm_body_layout_shape_marker(vm_body_layout_shape shape);

llvm::StringRef vm_status_trap_shape_marker(vm_status_trap_shape shape);

llvm::StringRef vm_terminal_trap_shape_marker(vm_terminal_trap_shape shape);

void note_vm_function_marker(llvm::Function& function, llvm::StringRef marker);

llvm::SmallVector<std::size_t, 32> build_vm_instruction_emission_order(
    const bytecode_program& program,
    llvm::ArrayRef<std::size_t> instruction_indices,
    std::uint64_t bytecode_seed,
    vm_body_layout_shape shape,
    std::uint64_t salt);

llvm::SmallVector<std::uint32_t, 8> build_vm_index_emission_order(
    std::uint32_t count,
    std::uint64_t bytecode_seed,
    vm_body_layout_shape shape,
    std::uint64_t salt);

void emit_vm_status_trap(llvm::Function& function,
                         llvm::BasicBlock* trap_block,
                         std::uint64_t bytecode_seed,
                         std::uint32_t choreography_detail,
                         std::uint64_t choreography_salt,
                         vm_status_trap_shape shape);

void emit_vm_terminal_trap(llvm::Function& function,
                           llvm::BasicBlock* trap_block,
                           const mba::builder_context& mba_context,
                           std::uint64_t salt,
                           vm_terminal_trap_shape shape);

llvm::BasicBlock* create_handler_success_route(rewrite_function_context& rewrite_context,
                                               llvm::BasicBlock* handler_block,
                                               std::size_t instruction_index);

void rewrite_function_body_state_islands(llvm::Function& function,
                                        const bytecode_program& program,
                                        const virtualization_options& options,
                                        llvm::StringRef symbol_tag,
                                        llvm::ArrayRef<llvm::BasicBlock*> old_blocks,
                                        std::uint64_t opaque_seed_base,
                                        std::uint64_t bytecode_seed,
                                        const opcode_permutation& opcode_map,
                                        std::uint32_t island_count);

}  // namespace obf::vm

#endif
