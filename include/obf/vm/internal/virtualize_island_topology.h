#ifndef OBF_VM_INTERNAL_VIRTUALIZE_ISLAND_TOPOLOGY_H
#define OBF_VM_INTERNAL_VIRTUALIZE_ISLAND_TOPOLOGY_H

#include "obf/vm/internal/virtualize_core.h"

#include <cstdint>
#include <string>
#include <vector>

namespace obf::vm {

struct micro_instruction;
struct bytecode_program;
struct serialized_bytecode_program;
struct bytecode_layout;
enum class vm_island_topology : std::uint32_t;

struct subisland_plan {
  std::vector<std::uint32_t> subhelper_for_instruction;
  llvm::SmallVector<llvm::SmallVector<std::size_t, 16>, 8> instructions;
  llvm::SmallVector<std::uint32_t, 8> route_order;
  bool capped = false;
  bool enabled() const { return instructions.size() >= 2; }
};

std::string make_vm_island_helper_name(llvm::Module& module,
                                       const rewrite_function_context& context,
                                       std::uint64_t island_index);

std::string make_vm_island_helper_name(llvm::Module& module,
                                       std::uint64_t bytecode_seed,
                                       std::uint64_t island_index);

std::string make_vm_subisland_helper_name(llvm::Module& module,
                                          std::uint64_t bytecode_seed,
                                          std::uint64_t island_index,
                                          std::uint64_t subisland_index);

std::string MakeVmIslandDecoyHelperName(llvm::Module& module,
                                        std::uint64_t bytecode_seed,
                                        std::uint64_t island_index);

llvm::SmallVector<std::size_t, 32> collect_island_instruction_indices(
    const bytecode_program& program,
    llvm::ArrayRef<std::uint32_t> island_for_instruction,
    std::uint32_t island_index);

subisland_plan build_subisland_plan(const bytecode_program& program,
                                    const serialized_bytecode_program& serialized,
                                    llvm::ArrayRef<std::size_t> owned_instructions,
                                    std::uint64_t bytecode_seed,
                                    std::uint32_t island_index);

bool should_use_state_islands(const bytecode_program& program,
                              vm_island_topology topology,
                              std::uint32_t island_count);

std::vector<std::uint32_t> assign_vm_instruction_islands(const bytecode_program& program,
                                                         std::uint64_t bytecode_seed,
                                                         std::uint32_t island_count);

VmDecoyRoutePlan BuildVmDecoyRoutePlan(const bytecode_program& program,
                                       llvm::ArrayRef<std::uint32_t> dispatch_index_for_instruction,
                                       llvm::ArrayRef<std::uint32_t> island_for_instruction,
                                       llvm::ArrayRef<std::size_t> owned_instructions,
                                       std::uint32_t real_instruction,
                                       std::uint32_t decoy_island,
                                       std::uint64_t salt);

std::uint32_t estimate_instruction_lowering_cost(const micro_instruction& instruction,
                                                 const bytecode_layout& layout);

std::uint32_t opcode_family(opcode op);

}  // namespace obf::vm

#endif
