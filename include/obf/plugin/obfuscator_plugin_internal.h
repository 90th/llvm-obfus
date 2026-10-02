#ifndef OBF_PLUGIN_OBFUSCATOR_PLUGIN_INTERNAL_H
#define OBF_PLUGIN_OBFUSCATOR_PLUGIN_INTERNAL_H

#include "obf/frontend/config.h"
#include "obf/plugin/internal/plugin_vm_types.h"
#include "obf/report/function_report.h"
#include "obf/plugin/stage_signatures.h"

// Option type declarations - minimal includes needed for build_*_options() signatures
// (These types are part of the internal API and must be exposed)
#include "obf/transforms/artifact_cleanup.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/function_outlining.h"
#include "obf/transforms/indirect_dispatch.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/mba.h"
#include "obf/transforms/opaque_gep.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"
#include "obf/transforms/self_checksum.h"
#include "obf/transforms/zero_comparison.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {

class CallBase;
class Function;
class Module;

}  // namespace llvm

namespace obf {

enum class obf_lto_mode {
  none,
  full,
  thin,
};

enum class lto_obligation_role {
  none,
  protected_entry,
  protected_covered,
  explicit_none,
  generated_internal,
  vm_implementation,
  vm_entry_thunk,
  raw_entry,
  raw_none,
};

struct lto_obligation_record {
  bool present = false;
  lto_obligation_role role = lto_obligation_role::none;
  std::uint64_t entry_identity = 0;
  std::string selector_name;
  std::string annotation;
  std::string selection_detail;
  policy_source source = policy_source::default_policy;
  function_policy policy;
  std::uint64_t config_identity = 0;
  std::uint64_t decision_seed = 0;
  bool requires_finalization = false;
  bool pinned_noinline = false;
  bool uses_target_cache = false;
  bool uses_shared_seed_resolver = false;
};

struct function_pipeline_state {
  llvm::Function* function = nullptr;
  function_report_entry report;
  mba::mba_shape_counts mba_counts;
  lto_obligation_record lto;
  bool skip_transform_stages = false;
};

bool is_obfuscation_enabled();
obfuscation_config load_active_config();
std::uint32_t effective_vm_mba_depth(const obfuscation_config& config);

std::uint64_t get_obf_seed_override();
obf_lto_mode get_active_lto_mode();
std::uint64_t compute_lto_config_identity(const obfuscation_config& config);
lto_obligation_record read_lto_obligation(const llvm::Function& function);
void apply_lto_obligation(llvm::Function& function, const lto_obligation_record& obligation);
void clear_lto_obligation(llvm::Function& function);
bool function_has_lto_obligation(const llvm::Function& function);

llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module& module, const obfuscation_config& config);

llvm::SmallVector<function_pipeline_state, 32>
build_lto_pipeline_state(llvm::Module& module, const obfuscation_config& config,
                         bool allow_unresolved_selectors);

artifact_cleanup_options build_artifact_cleanup_options(const obfuscation_config& config);

block_split_options build_block_split_options(const obfuscation_config& config,
                                              const policy_decision& decision);

string_encoding_options build_string_encoding_options(const obfuscation_config& config);

constant_encoding_options build_constant_encoding_options(const obfuscation_config& config,
                                                          const policy_decision& decision);

zero_comparison_options build_zero_comparison_options(const obfuscation_config& config,
                                                      const policy_decision& decision);

control_flattening_options build_control_flattening_options(const obfuscation_config& config,
                                                            const policy_decision& decision);

indirect_dispatch_options build_indirect_dispatch_options(const obfuscation_config& config,
                                                          const policy_decision& decision);

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config& config,
                                       const policy_decision& decision);

opaque_gep_options build_opaque_gep_options(const obfuscation_config& config,
                                            const policy_decision& decision);

function_outlining_options build_function_outlining_options(const obfuscation_config& config,
                                                            const policy_decision& decision);

bogus_control_flow_options build_bogus_control_flow_options(const obfuscation_config& config,
                                                            const policy_decision& decision);

opaque_predicate_options build_opaque_predicate_options(const obfuscation_config& config,
                                                        const policy_decision& decision);

llvm::SmallVector<transform_report_entry, 64>
build_transform_reports(llvm::Module& module,
                        const llvm::SmallVectorImpl<function_pipeline_state>& states,
                        const obfuscation_config& config);

void verify_changed_module(llvm::Module& module);

// All apply_*_stage() functions are declared in stage_signatures.h
// to reduce transitive includes and compilation coupling.

struct string_protection_owner {
  std::uint64_t seed = 0;
  protection_level level = protection_level::none;
};

std::optional<string_protection_owner>
read_string_protection_owner(const llvm::Function& function);

void record_string_protection_owner(llvm::Function& function,
                                    const policy_decision& decision);

llvm::StringMap<string_protection_owner>
build_string_protection_map(llvm::Module& module,
                            const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const virtualized_function_map* virtualized_functions = nullptr);

}  // namespace obf

#endif
