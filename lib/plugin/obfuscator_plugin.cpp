#include "obf/frontend/annotations.h"
#include "obf/frontend/config.h"
#include "obf/analysis/function_features.h"
#include "obf/report/function_report.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"
#include "obf/vm/candidate_analysis.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>

namespace obf {

namespace {

llvm::cl::opt<std::string> obf_config_path(
    "obf-config",
    llvm::cl::desc("Path to llvm-obfus milestone-zero YAML config"),
    llvm::cl::init(""));

struct function_pipeline_state {
  llvm::Function *function = nullptr;
  function_report_entry report;
};

obfuscation_config load_active_config() {
  if (obf_config_path.empty()) {
    return {};
  }

  llvm::Expected<obfuscation_config> config =
      load_config_from_file(obf_config_path);
  if (!config) {
    const std::string error_message = llvm::toString(config.takeError());
    llvm::report_fatal_error(llvm::StringRef(error_message));
  }

  return *config;
}

llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module &module, const obfuscation_config &config) {
  const function_annotation_map annotations = collect_function_annotations(module);

  llvm::SmallVector<function_pipeline_state, 32> states;
  states.reserve(module.size());

  for (llvm::Function &function : module) {
    function_report_entry report;
    report.features = collect_function_features(function);

    if (const std::string *annotation =
            find_function_annotation(annotations, function.getName())) {
      report.annotation = *annotation;
    }

    report.decision =
        select_policy(module, report.features, config, report.annotation);
    states.push_back({.function = &function, .report = std::move(report)});
  }

  return states;
}

template <typename Predicate>
llvm::StringMap<std::uint64_t>
build_function_seed_map(const llvm::SmallVectorImpl<function_pipeline_state> &states,
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

block_split_options build_block_split_options(const obfuscation_config &config,
                                              const policy_decision &decision) {
  block_split_options options;
  options.max_splits_per_function =
      config.block_split.max_splits_per_function;
  options.min_instructions_per_block =
      config.block_split.min_instructions_per_block;

  if (decision.policy.level == protection_level::light) {
    options.max_splits_per_function =
        std::min<std::size_t>(options.max_splits_per_function, 1);
  }

  return options;
}

string_encoding_options build_string_encoding_options(const obfuscation_config &config) {
  return {.min_string_length = config.string_encoding.min_string_length,
          .max_strings_per_module = config.string_encoding.max_strings_per_module,
          .ctor_priority = 0,
          .prefer_lazy_decode = config.string_encoding.prefer_lazy_decode,
          .allow_ctor_fallback = config.string_encoding.allow_ctor_fallback};
}

constant_encoding_options
build_constant_encoding_options(const obfuscation_config &config,
                                const policy_decision &decision) {
  constant_encoding_options options;
  options.max_constants_per_function =
      config.constant_encoding.max_constants_per_function;
  options.min_bit_width = config.constant_encoding.min_bit_width;

  if (decision.policy.level == protection_level::light) {
    options.max_constants_per_function =
        std::min<std::size_t>(options.max_constants_per_function, 2);
  }

  return options;
}

control_flattening_options
build_control_flattening_options(const obfuscation_config &,
                                 const policy_decision &decision) {
  control_flattening_options options;
  if (decision.policy.level == protection_level::strong) {
    options.max_blocks = 20;
    options.max_instructions = 192;
  }

  return options;
}

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config &,
                                       const policy_decision &decision) {
  instruction_substitution_options options;
  if (decision.policy.level == protection_level::strong) {
    options.max_substitutions_per_function = 6;
  } else {
    options.max_substitutions_per_function = 2;
  }

  return options;
}

bogus_control_flow_options
build_bogus_control_flow_options(const obfuscation_config &,
                                 const policy_decision &decision) {
  bogus_control_flow_options options;
  if (decision.policy.level == protection_level::strong) {
    options.max_insertions_per_function = 2;
  }

  return options;
}

opaque_predicate_options
build_opaque_predicate_options(const obfuscation_config &,
                               const policy_decision &decision) {
  opaque_predicate_options options;
  if (decision.policy.level == protection_level::strong) {
    options.max_insertions_per_function = 2;
  }

  return options;
}

transform_report_entry make_transform_report(llvm::StringRef pass,
                                             llvm::StringRef target_kind,
                                             llvm::StringRef target_name,
                                             bool applied, llvm::StringRef detail,
                                             std::size_t count) {
  return {.pass = pass.str(),
          .target_kind = target_kind.str(),
          .target_name = target_name.str(),
          .status = applied ? "applied" : "skipped",
          .detail = detail.str(),
          .count = count};
}

llvm::SmallVector<transform_report_entry, 64>
build_transform_reports(llvm::Module &module,
                        const llvm::SmallVectorImpl<function_pipeline_state> &states,
                        const obfuscation_config &config) {
  llvm::SmallVector<transform_report_entry, 64> reports;
  llvm::StringSet<> virtualized_functions;

  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (vm::analyze_candidate(*state.function).eligible) {
      virtualized_functions.insert(state.function->getName());
    }
  }

  for (const function_pipeline_state &state : states) {
    const llvm::Function *function = state.function;
    if (function == nullptr) {
      continue;
    }

    const bool suppressed_by_vm =
        virtualized_functions.contains(function->getName());

    const vm::candidate_result vm_result = vm::analyze_candidate(*function);
    if (!state.report.decision.policy.allow_vm) {
      reports.push_back(make_transform_report(
          "vm", "function", function->getName(), false,
          function->isDeclaration() ? "declaration" : "policy disallows vm", 0));
    } else {
      reports.push_back(make_transform_report(
          "vm", "function", function->getName(), vm_result.eligible,
          vm_result.detail, vm_result.eligible ? vm_result.instruction_count : 0));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("block_split", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_split) {
      reports.push_back(make_transform_report(
          "block_split", "function", function->getName(), false,
          function->isDeclaration() ? "declaration" : "policy disallows split",
          0));
    } else {
      const block_split_options options =
          build_block_split_options(config, state.report.decision);
      const block_split_result result =
          analyze_block_split(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report("block_split", "function",
                                              function->getName(),
                                              result.split_count > 0,
                                              result.detail, result.split_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("constant_encoding", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_constant_encoding) {
      reports.push_back(make_transform_report(
          "constant_encoding", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows constant encoding",
          0));
    } else {
      const constant_encoding_options options =
          build_constant_encoding_options(config, state.report.decision);
      const constant_encoding_result result =
          analyze_constant_encoding(*function, options, state.report.decision.seed);
      reports.push_back(make_transform_report(
          "constant_encoding", "function", function->getName(),
          result.encoded_count > 0, result.detail, result.encoded_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_instruction_substitution) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows instruction substitution",
          0));
    } else {
      const instruction_substitution_options options =
          build_instruction_substitution_options(config, state.report.decision);
      const instruction_substitution_result result =
          analyze_instruction_substitution(*function, options);
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(),
          result.substitution_count > 0, result.detail,
          result.substitution_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("control_flattening", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_flattening) {
      reports.push_back(make_transform_report(
          "control_flattening", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows flattening",
          0));
    } else {
      const control_flattening_options options =
          build_control_flattening_options(config, state.report.decision);
      const control_flattening_result result =
          analyze_control_flattening(*function, options);
      reports.push_back(make_transform_report(
          "control_flattening", "function", function->getName(),
          result.flattened, result.detail, result.state_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("opaque_predicates", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_opaque_predicates) {
      reports.push_back(make_transform_report(
          "opaque_predicates", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows opaque predicates",
          0));
    } else {
      const opaque_predicate_options options =
          build_opaque_predicate_options(config, state.report.decision);
      const opaque_predicate_result result =
          analyze_opaque_predicates(*function, options);
      reports.push_back(make_transform_report(
          "opaque_predicates", "function", function->getName(),
          result.insertion_count > 0, result.detail, result.insertion_count));
    }

    if (suppressed_by_vm) {
      reports.push_back(make_transform_report("bogus_control_flow", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (!state.report.decision.policy.allow_bogus_control_flow) {
      reports.push_back(make_transform_report(
          "bogus_control_flow", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows bogus control flow",
          0));
    } else {
      const bogus_control_flow_options options =
          build_bogus_control_flow_options(config, state.report.decision);
      const bogus_control_flow_result result =
          analyze_bogus_control_flow(*function, options);
      reports.push_back(make_transform_report(
          "bogus_control_flow", "function", function->getName(),
          result.insertion_count > 0, result.detail, result.insertion_count));
    }

  }

  const llvm::StringMap<std::uint64_t> string_function_seeds =
      build_function_seed_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });
  const string_encoding_options string_options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> string_results = analyze_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = string_function_seeds.find(function_name);
        if (iterator == string_function_seeds.end()) {
          return std::nullopt;
        }

        return iterator->second;
      },
      string_options, config.seed);

  for (const string_encoding_result &result : string_results) {
    const std::string detail =
        result.applied ? (to_string(result.mode) + ": " + result.detail)
                       : result.detail;
    const std::size_t count =
        (result.mode == string_encoding_mode::lazy_decode ||
         result.mode == string_encoding_mode::inline_stack_decode)
            ? result.rewritten_use_count
            : (result.applied ? 1U : 0U);
    transform_report_entry entry = make_transform_report(
        "string_encoding", "global", result.global_name, result.applied, detail,
        count);
    entry.has_strategy_payload = true;
    entry.strategy_kind = to_string(result.strategy_kind);
    entry.helper_shape = to_string(result.helper_shape);
    entry.key_schedule = to_string(result.key_schedule);
    entry.inline_eligible = result.inline_eligible;
    entry.inline_detail = result.inline_detail;
    entry.fallback_reason = result.fallback_reason;
    entry.merge_group = result.merge_group;
    entry.descriptor_index = result.descriptor_index;
    entry.protected_use_count = result.protected_use_count;
    entry.unprotected_use_count = result.unprotected_use_count;
    entry.use_kinds = result.use_kinds;
    reports.push_back(std::move(entry));
  }

  return reports;
}

void verify_changed_module(llvm::Module &module) {
  std::string error_text;
  llvm::raw_string_ostream stream(error_text);
  if (llvm::verifyModule(module, &stream)) {
    stream.flush();
    llvm::report_fatal_error(llvm::StringRef(error_text));
  }
}

bool should_skip_function(const function_pipeline_state &state,
                          const llvm::StringSet<> *skip_functions) {
  if (state.function == nullptr || state.function->isDeclaration()) {
    return true;
  }

  return skip_functions != nullptr &&
         skip_functions->contains(state.function->getName());
}

bool apply_block_split_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
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

llvm::StringSet<>
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state> &states) {
  llvm::StringSet<> virtualized_functions;

  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration() ||
        !state.report.decision.policy.allow_vm) {
      continue;
    }

    const vm::virtualization_result result =
        vm::run_virtualization(*state.function);
    if (result.virtualized) {
      virtualized_functions.insert(state.function->getName());
    }
  }

  return virtualized_functions;
}

bool apply_string_encoding_stage(
    llvm::Module &module,
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config) {
  const llvm::StringMap<std::uint64_t> protected_functions =
      build_function_seed_map(states, [](const function_policy &policy) {
        return policy.allow_string_encoding;
      });

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
      options, config.seed);

  return llvm::any_of(results, [](const string_encoding_result &result) {
    return result.applied;
  });
}

bool apply_constant_encoding_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_constant_encoding) {
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
    const llvm::StringSet<> *skip_functions = nullptr) {
  bool changed = false;

  for (const function_pipeline_state &state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    changed |= run_instruction_substitution(*state.function, options)
                   .substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_predicate_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
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
    const llvm::StringSet<> *skip_functions = nullptr) {
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

bool apply_bogus_control_flow_stage(
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const llvm::StringSet<> *skip_functions = nullptr) {
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

} // namespace

class feature_report_pass : public llvm::PassInfoMixin<feature_report_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    llvm::SmallVector<function_report_entry, 32> entries;
    entries.reserve(states.size());
    for (const function_pipeline_state &state : states) {
      entries.push_back(state.report);
    }

    const llvm::SmallVector<transform_report_entry, 64> transforms =
        build_transform_reports(module, states, config);

    llvm::outs() << format_feature_report(module.getName(), entries, transforms)
                 << '\n';
    return llvm::PreservedAnalyses::all();
  }
};

class block_split_pass : public llvm::PassInfoMixin<block_split_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_block_split_stage(states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);

    return llvm::PreservedAnalyses::none();
  }
};

class string_encoding_pass : public llvm::PassInfoMixin<string_encoding_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_string_encoding_stage(module, states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class vm_pass : public llvm::PassInfoMixin<vm_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const llvm::StringSet<> virtualized_functions = apply_vm_stage(states);
    if (virtualized_functions.empty()) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class constant_encoding_pass : public llvm::PassInfoMixin<constant_encoding_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_constant_encoding_stage(states, config);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class instruction_substitution_pass
    : public llvm::PassInfoMixin<instruction_substitution_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_instruction_substitution_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class control_flattening_pass
    : public llvm::PassInfoMixin<control_flattening_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(states, config);
    if (flattened_functions.empty()) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class opaque_predicate_pass
    : public llvm::PassInfoMixin<opaque_predicate_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_opaque_predicate_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class bogus_control_flow_pass
    : public llvm::PassInfoMixin<bogus_control_flow_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_bogus_control_flow_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class safe_pipeline_pass : public llvm::PassInfoMixin<safe_pipeline_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    bool changed = false;
    const llvm::StringSet<> virtualized_functions = apply_vm_stage(states);
    changed |= !virtualized_functions.empty();
    changed |= apply_string_encoding_stage(module, states, config);
    changed |= apply_constant_encoding_stage(states, config, &virtualized_functions);
    changed |= apply_instruction_substitution_stage(states, config,
                                                    &virtualized_functions);
    changed |= apply_opaque_predicate_stage(states, config, &virtualized_functions);
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(states, config, &virtualized_functions);
    changed |= !flattened_functions.empty();
    changed |= apply_bogus_control_flow_stage(states, config, &virtualized_functions);

    llvm::StringSet<> block_split_skips;
    for (const auto &entry : virtualized_functions) {
      block_split_skips.insert(entry.getKey());
    }
    for (const auto &entry : flattened_functions) {
      block_split_skips.insert(entry.getKey());
    }
    changed |= apply_block_split_stage(states, config, &block_split_skips);

    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

} // namespace obf

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "obf_plugin", "0.1",
          [](llvm::PassBuilder &pass_builder) {
            pass_builder.registerPipelineParsingCallback(
                [](llvm::StringRef name, llvm::ModulePassManager &module_pm,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (name == "obf-feature-report") {
                    module_pm.addPass(obf::feature_report_pass());
                    return true;
                  }

                  if (name == "obf-block-split" ||
                      name == "obf-split-scaffold") {
                    module_pm.addPass(obf::block_split_pass());
                    return true;
                  }

                  if (name == "obf-string-encode") {
                    module_pm.addPass(obf::string_encoding_pass());
                    return true;
                  }

                  if (name == "obf-vm") {
                    module_pm.addPass(obf::vm_pass());
                    return true;
                  }

                  if (name == "obf-constant-encode") {
                    module_pm.addPass(obf::constant_encoding_pass());
                    return true;
                  }

                  if (name == "obf-instruction-substitute") {
                    module_pm.addPass(obf::instruction_substitution_pass());
                    return true;
                  }

                  if (name == "obf-control-flatten") {
                    module_pm.addPass(obf::control_flattening_pass());
                    return true;
                  }

                  if (name == "obf-opaque-preds") {
                    module_pm.addPass(obf::opaque_predicate_pass());
                    return true;
                  }

                  if (name == "obf-bogus-cf") {
                    module_pm.addPass(obf::bogus_control_flow_pass());
                    return true;
                  }

                  if (name == "obf-safe-pipeline") {
                    module_pm.addPass(obf::safe_pipeline_pass());
                    return true;
                  }

                  return false;
                });
          }};
}
