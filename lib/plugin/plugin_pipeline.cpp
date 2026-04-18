#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/transforms/entropy_initialization.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <optional>
#include <vector>

namespace obf {

namespace {

bool should_skip_function(const function_pipeline_state &state,
                          const llvm::StringSet<> *skip_functions) {
  if (state.function == nullptr || state.function->isDeclaration()) {
    return true;
  }

  return skip_functions != nullptr &&
         skip_functions->contains(state.function->getName());
}

} // namespace

void verify_changed_module(llvm::Module &module) {
  std::string error_text;
  llvm::raw_string_ostream stream(error_text);
  if (llvm::verifyModule(module, &stream)) {
    stream.flush();
    llvm::report_fatal_error(llvm::StringRef(error_text));
  }
}

bool apply_block_split_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_split) {
      continue;
    }

    const block_split_options options =
        build_block_split_options(config, state.report.decision);
    changed |= run_block_split(*state.function, options,
                               state.report.decision.seed)
                   .split_count > 0;
  }

  return changed;
}

bool apply_string_encoding_stage(
    llvm::Module &module,
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const virtualized_function_map *virtualized_functions) {
  llvm::StringMap<std::uint64_t> protected_functions =
      build_function_seed_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });
  llvm::StringMap<protection_level> protected_levels =
      build_function_level_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });
  append_virtualized_function_seeds(
      protected_functions, virtualized_functions,
      [](const function_policy &policy) { return policy.allow_string_encoding; });
  append_virtualized_function_levels(
      protected_levels, virtualized_functions,
      [](const function_policy &policy) { return policy.allow_string_encoding; });

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = run_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) {
          return std::nullopt;
        }

        return iterator->second;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = protected_levels.find(function_name);
        if (iterator == protected_levels.end()) {
          return std::nullopt;
        }

        return iterator->second;
      },
      options, config.seed);

  return llvm::any_of(results, [](const string_encoding_result &result) {
    return result.applied;
  });
}

bool apply_entropy_initialization_stage(llvm::Module &module) {
  return RunEntropyInitialization(module);
}

bool apply_cfg_state_cleanup_stage(llvm::Module &module) {
  return RunCfgStateCleanup(module);
}

bool apply_artifact_cleanup_stage(llvm::Module &module,
                                  const obfuscation_config &config) {
  return RunArtifactCleanup(module, build_artifact_cleanup_options(config));
}

bool apply_constant_encoding_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_constant_encoding ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const constant_encoding_options options =
        build_constant_encoding_options(config, state.report.decision);
    changed |= run_constant_encoding(*state.function, options,
                                     state.report.decision.seed)
                   .encoded_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    changed |= run_instruction_substitution(*state.function, options)
                   .substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_opaque_gep) {
      continue;
    }

    const opaque_gep_options options =
        build_opaque_gep_options(config, state.report.decision);
    changed |= run_opaque_gep(*state.function, options).lowered_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy
             .allow_instruction_substitution) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(
            config, entry.second.state->report.decision);
    changed |= run_instruction_substitution(*function, options)
                   .substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_opaque_gep) {
      continue;
    }

    const opaque_gep_options options =
        build_opaque_gep_options(config, entry.second.state->report.decision);
    changed |= run_opaque_gep(*function, options).lowered_count > 0;
  }

  return changed;
}

bool apply_function_outlining_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_function_outlining) {
      continue;
    }

    const function_outlining_options options =
        build_function_outlining_options(config, state.report.decision);
    changed |= run_function_outlining(*state.function, options).shard_count > 0;
  }

  return changed;
}

bool apply_function_outlining_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_function_outlining) {
      continue;
    }

    const function_outlining_options options =
        build_function_outlining_options(config,
                                         entry.second.state->report.decision);
    changed |= run_function_outlining(*function, options).shard_count > 0;
  }

  return changed;
}

bool apply_opaque_predicate_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_opaque_predicates) {
      continue;
    }

    const opaque_predicate_options options =
        build_opaque_predicate_options(config, state.report.decision);
    changed |= run_opaque_predicates(*state.function, options).insertion_count > 0;
  }

  return changed;
}

llvm::StringSet<> apply_control_flattening_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  llvm::StringSet<> flattened_functions;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, state.report.decision);
    const control_flattening_result result =
        run_control_flattening(*state.function, options);
    if (result.flattened) {
      flattened_functions.insert(state.function->getName());
    }
  }

  return flattened_functions;
}

llvm::StringSet<> apply_control_flattening_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  llvm::StringSet<> flattened_functions;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config,
                                         entry.second.state->report.decision);
    const control_flattening_result result = run_control_flattening(*function, options);
    if (result.flattened) {
      flattened_functions.insert(function->getName());
    }
  }

  return flattened_functions;
}

bool apply_bogus_control_flow_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, state.report.decision);
    changed |= run_bogus_control_flow(*state.function, options)
                   .insertion_count > 0;
  }

  return changed;
}

bool apply_bogus_control_flow_to_functions(
    const virtualized_function_map &virtualized_functions,
    const obfuscation_config &config) {
  bool changed = false;

  for (const auto &entry : virtualized_functions) {
    llvm::Function *function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config,
                                         entry.second.state->report.decision);
    changed |= run_bogus_control_flow(*function, options).insertion_count > 0;
  }

  return changed;
}

} // namespace obf
