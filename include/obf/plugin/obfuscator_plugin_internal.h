#ifndef OBF_PLUGIN_OBFUSCATOR_PLUGIN_INTERNAL_H
#define OBF_PLUGIN_OBFUSCATOR_PLUGIN_INTERNAL_H

#include "obf/frontend/config.h"
#include "obf/report/function_report.h"
#include "obf/transforms/artifact_cleanup.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/function_outlining.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/opaque_gep.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Function.h"

#include <cstddef>
#include <cstdint>

namespace llvm {

class CallBase;
class Function;
class Module;

} // namespace llvm

namespace obf {

struct function_pipeline_state {
  llvm::Function *function = nullptr;
  function_report_entry report;
};

struct virtualized_call_site {
  llvm::CallBase *call = nullptr;
  std::uint64_t hidden_token = 0;
};

struct virtualized_function_binding {
  llvm::Function *interface_function = nullptr;
  llvm::Function *implementation_function = nullptr;
  const function_pipeline_state *state = nullptr;
  llvm::SmallVector<virtualized_call_site, 8> call_sites;
  std::uint64_t wrapper_token = 0;
};

using virtualized_function_map =
    llvm::StringMap<virtualized_function_binding>;

struct vm_target_candidate {
  llvm::Function *function = nullptr;
  const function_pipeline_state *state = nullptr;
  std::size_t nesting_depth = 0;
};

obfuscation_config load_active_config();

llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module &module, const obfuscation_config &config);

artifact_cleanup_options
build_artifact_cleanup_options(const obfuscation_config &config);

block_split_options build_block_split_options(const obfuscation_config &config,
                                              const policy_decision &decision);

string_encoding_options
build_string_encoding_options(const obfuscation_config &config);

constant_encoding_options
build_constant_encoding_options(const obfuscation_config &config,
                                const policy_decision &decision);

control_flattening_options
build_control_flattening_options(const obfuscation_config &config,
                                 const policy_decision &decision);

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config &config,
                                       const policy_decision &decision);

opaque_gep_options build_opaque_gep_options(const obfuscation_config &config,
                                            const policy_decision &decision);

function_outlining_options
build_function_outlining_options(const obfuscation_config &config,
                                 const policy_decision &decision);

bogus_control_flow_options
build_bogus_control_flow_options(const obfuscation_config &config,
                                 const policy_decision &decision);

opaque_predicate_options
build_opaque_predicate_options(const obfuscation_config &config,
                               const policy_decision &decision);

llvm::SmallVector<transform_report_entry, 64>
build_transform_reports(llvm::Module &module,
                        const llvm::SmallVectorImpl<function_pipeline_state> &states,
                        const obfuscation_config &config);

void verify_changed_module(llvm::Module &module);

bool apply_block_split_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_string_encoding_stage(
    llvm::Module &module,
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const virtualized_function_map *virtualized_functions = nullptr);

bool apply_entropy_initialization_stage(llvm::Module &module);

bool apply_cfg_state_cleanup_stage(llvm::Module &module);

bool apply_artifact_cleanup_stage(llvm::Module &module,
                                  const obfuscation_config &config);

bool apply_constant_encoding_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_opaque_gep_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_instruction_substitution_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config);

bool apply_opaque_gep_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config);

bool apply_function_outlining_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_function_outlining_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config);

bool apply_opaque_predicate_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

llvm::StringSet<> apply_control_flattening_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

llvm::StringSet<> apply_control_flattening_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config);

bool apply_bogus_control_flow_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr);

bool apply_bogus_control_flow_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config);

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state> &states,
               const obfuscation_config &config,
               const protection_level *only_level = nullptr);

bool rewrite_calls_to_virtualized_functions(
    llvm::Module &module,
    const virtualized_function_map &virtualized_functions,
    std::uint32_t mba_depth);

llvm::StringSet<> collect_virtualized_function_names(
    const virtualized_function_map &virtualized_functions);

void include_vm_parent_functions(
    llvm::StringSet<> &virtualized_names,
    const virtualized_function_map &virtualized_functions);

template <typename Predicate>
llvm::StringMap<std::uint64_t> build_function_seed_map(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    Predicate predicate) {
  llvm::StringMap<std::uint64_t> seeds;
  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration()) {
      continue;
    }

    if (!predicate(state.report.decision.policy)) {
      continue;
    }

    seeds[state.function->getName()] = state.report.decision.seed;
  }

  return seeds;
}

template <typename Predicate>
llvm::StringMap<protection_level> build_function_level_map(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    Predicate predicate) {
  llvm::StringMap<protection_level> levels;
  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration()) {
      continue;
    }

    if (!predicate(state.report.decision.policy)) {
      continue;
    }

    levels[state.function->getName()] = state.report.decision.policy.level;
  }

  return levels;
}

template <typename Predicate>
void append_virtualized_function_seeds(
    llvm::StringMap<std::uint64_t> &seeds,
    const virtualized_function_map *virtualized_functions, Predicate predicate) {
  if (virtualized_functions == nullptr) {
    return;
  }

  for (const auto &entry : *virtualized_functions) {
    const virtualized_function_binding &binding = entry.second;
    if (binding.state == nullptr ||
        !predicate(binding.state->report.decision.policy)) {
      continue;
    }

    const std::uint64_t seed = binding.state->report.decision.seed;
    if (binding.interface_function != nullptr) {
      seeds[binding.interface_function->getName()] = seed;
    }
    if (binding.implementation_function != nullptr) {
      seeds[binding.implementation_function->getName()] = seed;
    }
  }
}

template <typename Predicate>
void append_virtualized_function_levels(
    llvm::StringMap<protection_level> &levels,
    const virtualized_function_map *virtualized_functions, Predicate predicate) {
  if (virtualized_functions == nullptr) {
    return;
  }

  for (const auto &entry : *virtualized_functions) {
    const virtualized_function_binding &binding = entry.second;
    if (binding.state == nullptr ||
        !predicate(binding.state->report.decision.policy)) {
      continue;
    }

    const protection_level level = binding.state->report.decision.policy.level;
    if (binding.interface_function != nullptr) {
      levels[binding.interface_function->getName()] = level;
    }
    if (binding.implementation_function != nullptr) {
      levels[binding.implementation_function->getName()] = level;
    }
  }
}

} // namespace obf

#endif
