#pragma once

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Module.h"
#include "obf/frontend/config.h"

#include <cstdint>

namespace llvm {
class Function;
}

namespace obf {

// Forward declarations (opaque types to break coupling)
struct function_pipeline_state;
struct obfuscation_config;
struct virtualized_function_binding;
struct function_report_entry;
// Note: protection_level is defined in config.h (included above), no forward needed

// Typedefs
using virtualized_function_map = llvm::StringMap<virtualized_function_binding>;

// Core pipeline functions
llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module& module, const obfuscation_config& config);

// Stage application functions - all stages follow pattern:
// bool apply_*_stage(...) { ... return changed; }

bool apply_block_split_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                             const obfuscation_config& config,
                             const llvm::StringSet<>* skip_functions = nullptr);

bool apply_string_encoding_stage(llvm::Module& module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config,
                                 const virtualized_function_map* virtualized_functions = nullptr);

bool apply_entropy_initialization_stage(llvm::Module& module, std::uint64_t seed_override = 0);

bool apply_cfg_state_cleanup_stage(llvm::Module& module);

bool apply_artifact_cleanup_stage(llvm::Module& module, const obfuscation_config& config);

bool apply_constant_encoding_stage(llvm::Module& module,
                                   const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                   const obfuscation_config& config,
                                   const llvm::StringSet<>* skip_functions = nullptr);

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const llvm::StringSet<>* skip_functions = nullptr);

bool apply_opaque_gep_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const obfuscation_config& config,
                            const llvm::StringSet<>* skip_functions = nullptr);

bool apply_function_outlining_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                    const obfuscation_config& config,
                                    const llvm::StringSet<>* skip_functions = nullptr);

bool apply_opaque_predicate_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                  const obfuscation_config& config,
                                  const llvm::StringSet<>* skip_functions = nullptr);

bool apply_lifter_destruction_stage(llvm::Module& module,
                                    const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                    const obfuscation_config& config,
                                    const llvm::StringSet<>* skip_functions = nullptr);

llvm::StringSet<>
apply_control_flattening_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                               const obfuscation_config& config,
                               const llvm::StringSet<>* skip_functions = nullptr);

bool apply_bogus_control_flow_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                    const obfuscation_config& config,
                                    const llvm::StringSet<>* skip_functions = nullptr);

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
               const obfuscation_config& config,
               const protection_level* only_level = nullptr);

// Specialized stage variants (for VM-only functions)
bool apply_instruction_substitution_to_functions(
    const virtualized_function_map& virtualized_functions, const obfuscation_config& config);

bool apply_opaque_gep_to_functions(const virtualized_function_map& virtualized_functions,
                                   const obfuscation_config& config);

bool apply_function_outlining_to_functions(const virtualized_function_map& virtualized_functions,
                                           const obfuscation_config& config);

llvm::StringSet<>
apply_control_flattening_to_functions(const virtualized_function_map& virtualized_functions,
                                      const obfuscation_config& config);

bool apply_bogus_control_flow_to_functions(const virtualized_function_map& virtualized_functions,
                                           const obfuscation_config& config);

// VM rewriting and utilities
bool rewrite_calls_to_virtualized_functions(llvm::Module& module,
                                            const virtualized_function_map& virtualized_functions,
                                            std::uint32_t mba_depth);

llvm::StringSet<>
collect_virtualized_function_names(const virtualized_function_map& virtualized_functions);

void include_vm_parent_functions(llvm::StringSet<>& virtualized_names,
                                 const virtualized_function_map& virtualized_functions);

bool enforce_security_gates(llvm::Module& module,
                            const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const virtualized_function_map& virtualized_functions,
                            const obfuscation_config& config);

}  // namespace obf
