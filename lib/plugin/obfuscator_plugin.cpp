#include "obf/frontend/annotations.h"
#include "obf/frontend/config.h"
#include "obf/analysis/function_features.h"
#include "obf/report/function_report.h"
#include "obf/transforms/artifact_cleanup.h"
#include "obf/transforms/block_split.h"
#include "obf/transforms/bogus_control_flow.h"
#include "obf/transforms/constant_encoding.h"
#include "obf/transforms/control_flattening.h"
#include "obf/transforms/entropy_initialization.h"
#include "obf/transforms/function_outlining.h"
#include "obf/transforms/instruction_substitution.h"
#include "obf/transforms/mba.h"
#include "obf/transforms/opaque_gep.h"
#include "obf/transforms/opaque_predicates.h"
#include "obf/transforms/string_encoding.h"
#include "obf/vm/candidate_analysis.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <optional>

namespace obf {

namespace {

/// Returns true for levels that use the strong-classical transform tuning.
bool has_strong_classical(protection_level level) {
  return level == protection_level::strong ||
         level == protection_level::strong_vm;
}

/// Returns true for functions whose behavior is already sensitive enough that
/// callers/orchestrators should inherit stronger classical hardening.
bool is_orchestrator_seed_level(protection_level level) {
  return level == protection_level::strong || level == protection_level::vm ||
         level == protection_level::strong_vm;
}

bool is_orchestrator_promoted_level(protection_level level) {
  return level != protection_level::none;
}

bool is_user_pipeline_function(const llvm::Function &function) {
  const llvm::StringRef name = function.getName();
  return !name.starts_with("__obf_") && !name.starts_with("llvm.");
}

bool is_top_level_semantic_function(const llvm::Function &function) {
  return function.getName() == "main";
}

enum class orchestrator_observation_kind {
  top_level,
  control_flow,
  call_argument,
  return_value,
  memory_sink,
};

llvm::StringRef
describe_orchestrator_observation(orchestrator_observation_kind kind) {
  switch (kind) {
  case orchestrator_observation_kind::top_level:
    return "top-level protected call";
  case orchestrator_observation_kind::control_flow:
    return "protected result drives control flow";
  case orchestrator_observation_kind::call_argument:
    return "protected result escapes through a call";
  case orchestrator_observation_kind::return_value:
    return "protected result escapes through a return";
  case orchestrator_observation_kind::memory_sink:
    return "protected result escapes through memory";
  }

  return "protected orchestrator";
}

void append_policy_detail(std::string &detail, llvm::StringRef suffix) {
  if (!detail.empty()) {
    detail += "; ";
  }

  detail += suffix.str();
}

function_policy build_orchestrator_promotion_policy(
    const function_features &features) {
  function_policy policy = make_function_policy(protection_level::strong);
  if (!(features.has_exception_edges || features.has_inline_asm)) {
    return policy;
  }

  // Keep risky orchestrators on the safest non-none profile. This still gives
  // them string/constant coverage without re-enabling transforms that tend to
  // break invoke/asm-heavy wrappers.
  policy = make_function_policy(protection_level::light);
  policy.allow_instruction_substitution = false;
  policy.allow_function_outlining = false;
  policy.allow_bogus_control_flow = false;
  policy.allow_opaque_predicates = false;
  policy.allow_flattening = false;
  policy.allow_split = false;
  policy.allow_indirect_calls = false;
  policy.allow_vm = false;
  return policy;
}

std::optional<orchestrator_observation_kind>
find_protected_result_observation(const llvm::Value &root,
                                  const llvm::Function &owner) {
  llvm::SmallVector<const llvm::Value *, 16> worklist;
  llvm::SmallPtrSet<const llvm::Value *, 32> visited;
  worklist.push_back(&root);

  while (!worklist.empty()) {
    const llvm::Value *value = worklist.pop_back_val();
    if (!visited.insert(value).second) {
      continue;
    }

    for (const llvm::User *user : value->users()) {
      const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
      if (instruction == nullptr || instruction->getFunction() != &owner) {
        continue;
      }

      if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(instruction)) {
        if (branch->isConditional()) {
          return orchestrator_observation_kind::control_flow;
        }
      }

      if (llvm::isa<llvm::SwitchInst>(instruction) ||
          llvm::isa<llvm::SelectInst>(instruction) ||
          llvm::isa<llvm::ICmpInst>(instruction) ||
          llvm::isa<llvm::FCmpInst>(instruction)) {
        return orchestrator_observation_kind::control_flow;
      }

      if (llvm::isa<llvm::ReturnInst>(instruction)) {
        return orchestrator_observation_kind::return_value;
      }

      if (const auto *store = llvm::dyn_cast<llvm::StoreInst>(instruction)) {
        if (store->getValueOperand() == value) {
          const llvm::Value *pointer = llvm::getUnderlyingObject(
              store->getPointerOperand()->stripPointerCasts());
          if (!llvm::isa<llvm::AllocaInst>(pointer)) {
            return orchestrator_observation_kind::memory_sink;
          }
          worklist.push_back(pointer);
          continue;
        }
      }

      if (const auto *call = llvm::dyn_cast<llvm::CallBase>(instruction)) {
        if (call->getCalledOperand()->stripPointerCasts() != value) {
          return orchestrator_observation_kind::call_argument;
        }
      }

      worklist.push_back(instruction);
    }
  }

  return std::nullopt;
}

struct orchestrator_promotion_reason {
  llvm::StringRef callee_name;
  orchestrator_observation_kind observation =
      orchestrator_observation_kind::top_level;
};

std::optional<orchestrator_promotion_reason>
find_orchestrator_promotion_reason(const llvm::Function &function,
                                   const llvm::StringSet<> &sensitive_functions) {
  std::optional<llvm::StringRef> first_sensitive_callee;

  for (const llvm::BasicBlock &block : function) {
    for (const llvm::Instruction &instruction : block) {
      const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call == nullptr) {
        continue;
      }

      const llvm::Value *called_operand =
          call->getCalledOperand()->stripPointerCasts();
      const auto *callee = llvm::dyn_cast<llvm::Function>(called_operand);
      if (callee == nullptr || !sensitive_functions.contains(callee->getName())) {
        continue;
      }

      if (!first_sensitive_callee.has_value()) {
        first_sensitive_callee = callee->getName();
      }

      if (is_top_level_semantic_function(function)) {
        return orchestrator_promotion_reason{
            .callee_name = callee->getName(),
            .observation = orchestrator_observation_kind::top_level};
      }

      if (!call->getType()->isVoidTy()) {
        if (const auto observation =
                find_protected_result_observation(*call, function)) {
          return orchestrator_promotion_reason{.callee_name = callee->getName(),
                                               .observation = *observation};
        }
      }
    }
  }

  if (first_sensitive_callee.has_value() && is_top_level_semantic_function(function)) {
    return orchestrator_promotion_reason{.callee_name = *first_sensitive_callee,
                                         .observation =
                                             orchestrator_observation_kind::top_level};
  }

  return std::nullopt;
}

llvm::cl::opt<std::string> obf_config_path(
    "obf-config",
    llvm::cl::desc("Path to llvm-obfus milestone-zero YAML config"),
    llvm::cl::init(""));

llvm::cl::opt<std::uint64_t> obf_seed_override(
    "obf-seed",
    llvm::cl::desc("Overrides the top-level obfuscation seed"),
    llvm::cl::init(0));

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

void apply_orchestrator_policy_promotions(
    llvm::SmallVectorImpl<function_pipeline_state> &states) {
  llvm::StringSet<> sensitive_functions;
  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration() ||
        !is_user_pipeline_function(*state.function)) {
      continue;
    }

    if (is_orchestrator_seed_level(state.report.decision.policy.level)) {
      sensitive_functions.insert(state.function->getName());
    }
  }

  bool changed = true;
  while (changed) {
    changed = false;

    for (function_pipeline_state &state : states) {
      llvm::Function *function = state.function;
      if (function == nullptr || function->isDeclaration() ||
          !is_user_pipeline_function(*function) ||
          has_strong_classical(state.report.decision.policy.level)) {
        continue;
      }

      const auto reason =
          find_orchestrator_promotion_reason(*function, sensitive_functions);
      if (!reason.has_value()) {
        continue;
      }

      const function_policy promoted_policy =
          build_orchestrator_promotion_policy(state.report.features);
      if (promoted_policy.level == state.report.decision.policy.level) {
        continue;
      }

      state.report.decision.policy = promoted_policy;
      append_policy_detail(
          state.report.decision.detail,
          llvm::formatv("orchestrator promotion raised to {0} via protected callee {1} ({2})",
                        to_string(promoted_policy.level), reason->callee_name,
                        describe_orchestrator_observation(reason->observation))
              .str());
      if (is_orchestrator_promoted_level(promoted_policy.level)) {
        sensitive_functions.insert(function->getName());
      }
      changed = true;
    }
  }
}

obfuscation_config load_active_config() {
  obfuscation_config config;
  if (obf_config_path.empty()) {
    config = {};
  } else {
    llvm::Expected<obfuscation_config> loaded_config =
        load_config_from_file(obf_config_path);
    if (!loaded_config) {
      const std::string error_message = llvm::toString(loaded_config.takeError());
      llvm::report_fatal_error(llvm::StringRef(error_message));
    }

    config = *loaded_config;
  }

  if (obf_seed_override != 0) {
    config.seed = obf_seed_override;
  }

  return config;
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

  apply_orchestrator_policy_promotions(states);

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
    if (binding.state == nullptr || !predicate(binding.state->report.decision.policy)) {
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
    if (binding.state == nullptr || !predicate(binding.state->report.decision.policy)) {
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

artifact_cleanup_options
build_artifact_cleanup_options(const obfuscation_config &config) {
  artifact_cleanup_options options;
  options.seed = config.seed;
  return options;
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

  options.mba_depth = config.mba.depth;
  return options;
}

control_flattening_options
build_control_flattening_options(const obfuscation_config &,
                                 const policy_decision &decision) {
  control_flattening_options options;
  options.seed = decision.seed;
  if (has_strong_classical(decision.policy.level)) {
    options.max_blocks = 20;
    options.max_instructions = 192;
    options.max_decoy_states = 3;
  }

  return options;
}

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config &config,
                                       const policy_decision &decision) {
  instruction_substitution_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_substitutions_per_function = 6;
  } else {
    options.max_substitutions_per_function = 2;
  }

  options.mba_depth = config.mba.depth;
  return options;
}

opaque_gep_options build_opaque_gep_options(const obfuscation_config &config,
                                            const policy_decision &) {
  opaque_gep_options options;
  options.mba_depth = config.mba.depth;
  return options;
}

function_outlining_options
build_function_outlining_options(const obfuscation_config &config,
                                 const policy_decision &decision) {
  function_outlining_options options;
  options.mba_depth = config.mba.depth;
  options.seed = decision.seed;
  if (has_strong_classical(decision.policy.level)) {
    options.min_cluster_size = 2;
    options.max_cluster_size = 4;
  }

  return options;
}

bogus_control_flow_options
build_bogus_control_flow_options(const obfuscation_config &config,
                                 const policy_decision &decision) {
  bogus_control_flow_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_insertions_per_function = 2;
  }

  options.mba_depth = config.mba.depth;
  return options;
}

opaque_predicate_options
build_opaque_predicate_options(const obfuscation_config &config,
                               const policy_decision &decision) {
  opaque_predicate_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_insertions_per_function = 2;
  }

  options.mba_depth = config.mba.depth;
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
        virtualized_functions.contains(function->getName()) &&
        state.report.decision.policy.level != protection_level::strong_vm;
    const bool deferred_to_vm_hardening =
        virtualized_functions.contains(function->getName()) &&
        state.report.decision.policy.level == protection_level::strong_vm;

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
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report(
          "instruction_substitution", "function", function->getName(), false,
          "deferred to vm hardening", 0));
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
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("control_flattening", "function",
                                              function->getName(), false,
                                              "deferred to vm hardening", 0));
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
      reports.push_back(make_transform_report("function_outlining", "function",
                                              function->getName(), false,
                                              "suppressed after vm", 0));
    } else if (deferred_to_vm_hardening) {
      reports.push_back(make_transform_report("function_outlining", "function",
                                              function->getName(), false,
                                              "deferred to vm hardening", 0));
    } else if (!state.report.decision.policy.allow_function_outlining) {
      reports.push_back(make_transform_report(
          "function_outlining", "function", function->getName(), false,
          function->isDeclaration() ? "declaration"
                                    : "policy disallows function outlining",
          0));
    } else {
      const function_outlining_options options =
          build_function_outlining_options(config, state.report.decision);
      const function_outlining_result result =
          analyze_function_outlining(*function, options);
      reports.push_back(make_transform_report(
          "function_outlining", "function", function->getName(),
          result.shard_count > 0, result.detail, result.shard_count));
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
  const llvm::StringMap<protection_level> string_function_levels =
      build_function_level_map(states, [](const function_policy &policy) {
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
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = string_function_levels.find(function_name);
        if (iterator == string_function_levels.end()) {
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

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_vm_hidden_token(llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal) {
  std::uint64_t seed =
      static_cast<std::uint64_t>(llvm::hash_value(callee_name));
  seed = mix_vm_handshake_seed(
      seed, static_cast<std::uint64_t>(llvm::hash_value(caller_name)));
  seed = mix_vm_handshake_seed(seed, ordinal + 1);
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

std::uint64_t derive_vm_wrapper_token(llvm::StringRef function_name) {
  return derive_vm_hidden_token(function_name, function_name, 0x51f15eedULL);
}

std::string build_vm_region_helper_name(llvm::Function &function,
                                        std::uint64_t ordinal) {
  return llvm::formatv("__obf_vm_region_{0}_{1:x}", function.getName(),
                       ordinal + 1)
      .str();
}

struct vm_region_candidate {
  llvm::BasicBlock *header = nullptr;
  llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks;
  std::size_t score = 0;
};

llvm::SmallVector<vm_region_candidate, 8>
find_regional_vm_candidates(llvm::Function &function,
                            const llvm::StringSet<> &skip_functions) {
  llvm::SmallVector<vm_region_candidate, 8> candidates;
  if (skip_functions.contains(function.getName())) {
    return candidates;
  }

  for (llvm::BasicBlock &block : function) {
    if (block.getName().starts_with("entry.obf.vm") ||
        block.getName().starts_with("trap.obf.vm") ||
        block.getName().starts_with("vm.")) {
      continue;
    }

    auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) {
      continue;
    }

    const auto append_candidate = [&](llvm::SmallVectorImpl<llvm::BasicBlock *> &region_blocks) {
      llvm::CodeExtractorAnalysisCache cache(function);
      llvm::DominatorTree dom_tree(function);
      llvm::AssumptionCache assumption_cache(function);
      llvm::CodeExtractor extractor(region_blocks, &dom_tree,
                                    /*AggregateArgs=*/false,
                                    /*BFI=*/nullptr, /*BPI=*/nullptr,
                                    &assumption_cache,
                                    /*AllowVarArgs=*/false,
                                    /*AllowAlloca=*/false,
                                    /*AllocationBlock=*/nullptr,
                                    "obf.vm.region.check");
      if (!extractor.isEligible()) {
        return;
      }

      std::size_t instruction_count = 0;
      for (llvm::BasicBlock *region_block : region_blocks) {
        instruction_count += region_block->size();
      }
      llvm::SmallVector<llvm::BasicBlock *, 8> stored_blocks(region_blocks.begin(),
                                                             region_blocks.end());
      candidates.push_back(vm_region_candidate{.header = &block,
                                               .region_blocks = std::move(stored_blocks),
                                               .score = instruction_count});
    };

    llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks;
    llvm::BasicBlock *true_block = branch->getSuccessor(0);
    llvm::BasicBlock *false_block = branch->getSuccessor(1);
    if (true_block != false_block && llvm::pred_size(true_block) == 1 &&
        llvm::pred_size(false_block) == 1) {
      auto *true_term = llvm::dyn_cast<llvm::BranchInst>(true_block->getTerminator());
      auto *false_term = llvm::dyn_cast<llvm::BranchInst>(false_block->getTerminator());
      if (true_term != nullptr && false_term != nullptr &&
          true_term->isUnconditional() && false_term->isUnconditional() &&
          true_term->getSuccessor(0) == false_term->getSuccessor(0)) {
        llvm::BasicBlock *merge_block = true_term->getSuccessor(0);
        if (merge_block != &block && merge_block != true_block &&
            merge_block != false_block && llvm::pred_size(merge_block) == 2) {
          region_blocks = {&block, true_block, false_block};
          append_candidate(region_blocks);
        }
      }
    }

    for (llvm::BasicBlock *successor : branch->successors()) {
      if (successor == nullptr || successor == &block || llvm::pred_size(successor) != 1) {
        continue;
      }

      auto *succ_term = llvm::dyn_cast<llvm::BranchInst>(successor->getTerminator());
      if (succ_term != nullptr && succ_term->isUnconditional()) {
        region_blocks = {&block, successor};
        append_candidate(region_blocks);
      }
    }
  }

  llvm::sort(candidates, [](const vm_region_candidate &lhs,
                            const vm_region_candidate &rhs) {
    if (lhs.score != rhs.score) {
      return lhs.score > rhs.score;
    }
    return lhs.header->getName() < rhs.header->getName();
  });
  return candidates;
}

bool can_virtualize_extracted_region(llvm::Function &function,
                                     const vm_region_candidate &candidate,
                                     std::uint64_t helper_ordinal) {
  llvm::ValueToValueMapTy value_map;
  llvm::Function *clone = llvm::CloneFunction(&function, value_map);
  if (clone == nullptr) {
    return false;
  }

  clone->setName(build_vm_region_helper_name(function, helper_ordinal) + ".probe");
  llvm::BasicBlock *clone_header =
      llvm::cast<llvm::BasicBlock>(value_map.lookup(candidate.header));
  llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks;
  region_blocks.reserve(candidate.region_blocks.size());
  region_blocks.push_back(clone_header);
  for (std::size_t region_index = 1; region_index < candidate.region_blocks.size();
       ++region_index) {
    llvm::BasicBlock *region_block = candidate.region_blocks[region_index];
    region_blocks.push_back(llvm::cast<llvm::BasicBlock>(value_map.lookup(region_block)));
  }

  llvm::CodeExtractorAnalysisCache cache(*clone);
  llvm::DominatorTree dom_tree(*clone);
  llvm::AssumptionCache assumption_cache(*clone);
  llvm::CodeExtractor extractor(region_blocks, &dom_tree,
                                /*AggregateArgs=*/false,
                                /*BFI=*/nullptr, /*BPI=*/nullptr,
                                &assumption_cache,
                                /*AllowVarArgs=*/false,
                                /*AllowAlloca=*/false,
                                /*AllocationBlock=*/nullptr,
                                "obf.vm.region.probe");
  if (!extractor.isEligible()) {
    clone->eraseFromParent();
    return false;
  }

  llvm::SetVector<llvm::Value *> inputs;
  llvm::SetVector<llvm::Value *> outputs;
  llvm::Function *extracted = extractor.extractCodeRegion(cache, inputs, outputs);
  bool eligible = extracted != nullptr && vm::analyze_candidate(*extracted).eligible;
  if (extracted != nullptr) {
    extracted->eraseFromParent();
  }
  clone->eraseFromParent();
  return eligible;
}

llvm::Function *extract_regional_vm_helper(llvm::Function &function,
                                           const vm_region_candidate &candidate,
                                           std::uint64_t helper_ordinal) {
  llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks(candidate.region_blocks.begin(),
                                                         candidate.region_blocks.end());
  llvm::CodeExtractorAnalysisCache cache(function);
  llvm::DominatorTree dom_tree(function);
  llvm::AssumptionCache assumption_cache(function);
  llvm::CodeExtractor extractor(region_blocks, &dom_tree,
                                /*AggregateArgs=*/false,
                                /*BFI=*/nullptr, /*BPI=*/nullptr,
                                &assumption_cache,
                                /*AllowVarArgs=*/false,
                                /*AllowAlloca=*/false,
                                /*AllocationBlock=*/nullptr,
                                build_vm_region_helper_name(function, helper_ordinal));
  if (!extractor.isEligible()) {
    return nullptr;
  }

  llvm::Function *helper = extractor.extractCodeRegion(cache);
  if (helper == nullptr) {
    return nullptr;
  }

  helper->setName(build_vm_region_helper_name(function, helper_ordinal));
  helper->setLinkage(llvm::GlobalValue::InternalLinkage);
  helper->setDSOLocal(true);
  return helper;
}

bool collect_regional_vm_targets(
    llvm::Function &function, const function_pipeline_state &state,
    llvm::StringSet<> &skip_functions, std::uint64_t &helper_ordinal,
    std::size_t nesting_depth, std::size_t max_nesting_depth,
    std::size_t max_regions,
    llvm::SmallVectorImpl<vm_target_candidate> &targets) {
  bool extracted_any = false;
  std::size_t extracted_count = 0;
  while (extracted_count < max_regions) {
    const llvm::SmallVector<vm_region_candidate, 8> candidates =
        find_regional_vm_candidates(function, skip_functions);
    bool extracted_this_round = false;
    for (const vm_region_candidate &candidate : candidates) {
      if (!can_virtualize_extracted_region(function, candidate, helper_ordinal)) {
        continue;
      }

      llvm::Function *helper =
          extract_regional_vm_helper(function, candidate, helper_ordinal++);
      if (helper == nullptr) {
        continue;
      }

      llvm::SmallVector<vm_target_candidate, 4> nested_targets;
      if (nesting_depth < max_nesting_depth) {
        (void)collect_regional_vm_targets(*helper, state, skip_functions,
                                          helper_ordinal, nesting_depth + 1,
                                          max_nesting_depth,
                                          /*max_regions=*/1, nested_targets);
      }

      if (vm::analyze_candidate(*helper).eligible) {
        targets.push_back(
            {.function = helper, .state = &state, .nesting_depth = nesting_depth + 1});
      }
      for (const vm_target_candidate &nested_target : nested_targets) {
        targets.push_back(nested_target);
      }

      extracted_any = true;
      extracted_this_round = true;
      ++extracted_count;
      break;
    }

    if (!extracted_this_round) {
      break;
    }
  }

  return extracted_any;
}

llvm::SmallVector<vm_target_candidate, 8>
discover_vm_targets_for_state(const function_pipeline_state &state,
                              llvm::StringSet<> &skip_functions,
                              std::uint64_t &helper_ordinal) {
  llvm::SmallVector<vm_target_candidate, 8> targets;
  if (state.function == nullptr || state.function->isDeclaration() ||
      skip_functions.contains(state.function->getName())) {
    return targets;
  }

  const vm::candidate_result whole_function_analysis =
      vm::analyze_candidate(*state.function);

  if (state.report.decision.policy.level == protection_level::strong_vm) {
    // When the whole function is already VM-eligible, prefer full-function
    // virtualization over regional extraction so we do not leave a residual
    // parent body behind unnecessarily.
    if (whole_function_analysis.eligible) {
      targets.push_back(
          {.function = state.function, .state = &state, .nesting_depth = 0});
      return targets;
    }

    const bool extracted_regions = collect_regional_vm_targets(
        *state.function, state, skip_functions, helper_ordinal,
        /*nesting_depth=*/0,
        /*max_nesting_depth=*/1,
        /*max_regions=*/2, targets);
    if (extracted_regions) {
      return targets;
    }
  }

  if (whole_function_analysis.eligible) {
    targets.push_back({.function = state.function, .state = &state, .nesting_depth = 0});
  }
  return targets;
}

llvm::Value *build_hidden_token_value(llvm::IRBuilder<> &builder,
                                      llvm::Function &owner,
                                      llvm::StringRef prefix,
                                      std::uint64_t token,
                                      std::uint32_t mba_depth,
                                      std::uint64_t salt) {
  mba::builder_context context =
      mba::get_or_create_builder_context(owner, prefix, token ^ salt);
  context.depth = mba_depth;
  return mba::create_opaque_integer(builder, builder.getInt64Ty(), context,
                                    llvm::APInt(64, token), salt,
                                    (prefix + ".token").str());
}

llvm::Function *clone_vm_implementation(llvm::Function &interface_function) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  llvm::SmallVector<llvm::Type *, 8> parameter_types;
  parameter_types.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument &argument : interface_function.args()) {
    parameter_types.push_back(argument.getType());
  }
  parameter_types.push_back(llvm::Type::getInt64Ty(module->getContext()));

  auto *implementation_type = llvm::FunctionType::get(
      interface_function.getReturnType(), parameter_types, /*isVarArg=*/false);
  auto *implementation_function = llvm::Function::Create(
      implementation_type, llvm::GlobalValue::ExternalLinkage,
      ("__obf_vm_impl_" + interface_function.getName()).str(), module);
  implementation_function->setCallingConv(interface_function.getCallingConv());
  implementation_function->setAttributes(interface_function.getAttributes());
  implementation_function->setDSOLocal(true);

  llvm::ValueToValueMapTy value_map;
  auto implementation_arg = implementation_function->arg_begin();
  for (llvm::Argument &argument : interface_function.args()) {
    implementation_arg->setName(argument.getName());
    value_map[&argument] = &*implementation_arg++;
  }
  implementation_arg->setName("obf.hidden_token");

  llvm::SmallVector<llvm::ReturnInst *, 8> returns;
  llvm::CloneFunctionInto(implementation_function, &interface_function, value_map,
                          llvm::CloneFunctionChangeType::LocalChangesOnly,
                          returns);
  return implementation_function;
}

llvm::Value *decode_virtualized_integer_return(
    llvm::IRBuilder<> &builder, llvm::Function &owner,
    llvm::StringRef callee_name, llvm::Value *encoded_ret, llvm::Value *hidden_token,
    std::uint64_t token_seed, std::uint32_t mba_depth);

void rewrite_vm_interface_wrapper(llvm::Function &interface_function,
                                  llvm::Function &implementation_function,
                                  std::uint64_t wrapper_token,
                                  std::uint32_t mba_depth) {
  interface_function.deleteBody();

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(
      interface_function.getContext(), "entry.obf.vm.wrapper",
      &interface_function);
  llvm::IRBuilder<> builder(entry);
  llvm::Value *hidden_token = build_hidden_token_value(
      builder, interface_function,
      (interface_function.getName() + ".obf.wrapper").str(), wrapper_token,
      mba_depth, 0x6000ULL);

  llvm::SmallVector<llvm::Value *, 8> arguments;
  arguments.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument &argument : interface_function.args()) {
    arguments.push_back(&argument);
  }
  arguments.push_back(hidden_token);

  auto *call = builder.CreateCall(implementation_function.getFunctionType(),
                                  &implementation_function, arguments,
                                  interface_function.getReturnType()->isVoidTy()
                                      ? ""
                                      : (interface_function.getName() +
                                         ".obf.wrapper.call")
                                            .str());
  call->setCallingConv(interface_function.getCallingConv());
  call->setAttributes(implementation_function.getAttributes());
  if (interface_function.getReturnType()->isVoidTy()) {
    builder.CreateRetVoid();
  } else {
    llvm::Value *wrapper_ret = call;
    if (interface_function.getReturnType()->isIntegerTy()) {
      wrapper_ret = decode_virtualized_integer_return(
          builder, interface_function, interface_function.getName(), call,
          hidden_token, wrapper_token, mba_depth);
    }
    builder.CreateRet(wrapper_ret);
  }
}

virtualized_function_binding
prepare_virtualized_function_binding(const function_pipeline_state &state,
                                     std::uint32_t mba_depth) {
  virtualized_function_binding binding;
  llvm::Function *interface_function = state.function;
  if (interface_function == nullptr || interface_function->isDeclaration()) {
    return binding;
  }

  llvm::SmallVector<llvm::CallBase *, 16> direct_call_sites;
  for (llvm::User *user : interface_function->users()) {
    auto *call = llvm::dyn_cast<llvm::CallBase>(user);
    if (call == nullptr ||
        call->getCalledOperand()->stripPointerCasts() != interface_function) {
      continue;
    }
    direct_call_sites.push_back(call);
  }

  llvm::Function *implementation_function =
      clone_vm_implementation(*interface_function);
  if (implementation_function == nullptr) {
    return binding;
  }

  binding.interface_function = interface_function;
  binding.implementation_function = implementation_function;
  binding.state = &state;
  binding.wrapper_token = derive_vm_wrapper_token(interface_function->getName());

  std::uint64_t callsite_ordinal = 0;
  for (llvm::CallBase *call : direct_call_sites) {
    llvm::Function *caller = call->getFunction();
    if (caller == nullptr) {
      continue;
    }

    binding.call_sites.push_back(
        {.call = call,
         .hidden_token = derive_vm_hidden_token(interface_function->getName(),
                                                caller->getName(),
                                                callsite_ordinal++)});
  }

  rewrite_vm_interface_wrapper(*interface_function, *implementation_function,
                               binding.wrapper_token, mba_depth);
  return binding;
}

llvm::APInt derive_vm_target_key(const llvm::Function &function,
                                 llvm::IntegerType *ptr_int_type) {
  std::uint64_t key_word =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName()));
  key_word ^= static_cast<std::uint64_t>(ptr_int_type->getBitWidth()) << 32;
  return llvm::APInt(ptr_int_type->getBitWidth(),
                     key_word == 0 ? 0xa55aa55aULL : key_word,
                     /*isSigned=*/false, /*implicitTrunc=*/true);
}

/// Sentinel stored in the lazy-resolution slot to indicate "not yet resolved".
/// Using ~key guarantees decoding would yield all-ones (never a valid code
/// pointer), while being trivially distinguishable from any real encoded target.
llvm::APInt derive_vm_target_sentinel(const llvm::APInt &key) {
  return ~key;
}

llvm::GlobalVariable *get_or_create_vm_target_global(llvm::Function &function) {
  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const std::string global_name =
      ("__obf_vm_target_" + function.getName()).str();
  const llvm::DataLayout &data_layout = module->getDataLayout();
  auto *ptr_int_type =
      data_layout.getIntPtrType(module->getContext(), function.getAddressSpace());
  const llvm::APInt key = derive_vm_target_key(function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);

  if (llvm::GlobalVariable *existing = module->getNamedGlobal(global_name)) {
    return existing;
  }

  auto *target_global = new llvm::GlobalVariable(
      *module, ptr_int_type, false, llvm::GlobalValue::PrivateLinkage,
      llvm::ConstantInt::get(ptr_int_type, sentinel), global_name);
  return target_global;
}

llvm::GlobalVariable *
get_or_create_vm_decode_key_global(llvm::Module &module,
                                   llvm::IntegerType *ptr_int_type,
                                   llvm::StringRef callee_name,
                                   const llvm::APInt &key) {
  const std::string global_name = ("__obf_vm_key_" + callee_name).str();
  if (auto *existing = module.getNamedGlobal(global_name)) {
    return existing;
  }

  return new llvm::GlobalVariable(module, ptr_int_type, /*isConstant=*/false,
                                  llvm::GlobalValue::PrivateLinkage,
                                  llvm::ConstantInt::get(ptr_int_type, key),
                                  global_name);
}

llvm::Value *decode_virtualized_integer_return(
    llvm::IRBuilder<> &builder, llvm::Function &owner,
    llvm::StringRef callee_name, llvm::Value *encoded_ret, llvm::Value *hidden_token,
    std::uint64_t token_seed, std::uint32_t mba_depth) {
  llvm::Module *module = owner.getParent();
  if (module == nullptr || !encoded_ret->getType()->isIntegerTy()) {
    return encoded_ret;
  }

  llvm::GlobalVariable *retkey_global =
      module->getNamedGlobal(("__obf_vm_retkey_" + callee_name).str());
  if (retkey_global == nullptr) {
    return encoded_ret;
  }

  auto *retkey_load = builder.CreateLoad(builder.getInt64Ty(), retkey_global,
                                         callee_name.str() + ".obf.retkey");
  llvm::Value *token_for_ret = hidden_token;
  if (token_for_ret->getType() != builder.getInt64Ty()) {
    token_for_ret = builder.CreateZExtOrTrunc(
        token_for_ret, builder.getInt64Ty(),
        callee_name.str() + ".obf.rettoken.cast");
  }

  llvm::Value *token_bound_retkey = mba::create_xor(
      builder, retkey_load, token_for_ret,
      mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                           .seed_base = token_seed ^ 0x731000ULL,
                           .depth = mba_depth},
      0x731000ULL + token_seed, (callee_name + ".obf.retkey.bound").str());
  llvm::Value *retkey_cast = token_bound_retkey;
  if (encoded_ret->getType() != builder.getInt64Ty()) {
    retkey_cast = builder.CreateZExtOrTrunc(
        token_bound_retkey, encoded_ret->getType(),
        callee_name.str() + ".obf.retkey.cast");
  }

  mba::builder_context decode_context = mba::get_or_create_builder_context(
      owner, (callee_name + ".obf.ret").str(), token_seed ^ 0x730000ULL);
  decode_context.depth = mba_depth;
  return mba::create_xor(builder, encoded_ret, retkey_cast, decode_context,
                         0x730000ULL + token_seed,
                         (callee_name + ".obf.retdec").str());
}

bool rewrite_calls_to_virtualized_function(
    const virtualized_function_binding &binding, std::uint32_t mba_depth) {
  if (binding.interface_function == nullptr ||
      binding.implementation_function == nullptr) {
    return false;
  }

  llvm::Function &function = *binding.interface_function;
  llvm::Function &implementation_function = *binding.implementation_function;
  llvm::GlobalVariable *target_global = get_or_create_vm_target_global(function);
  if (target_global == nullptr) {
    return false;
  }

  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  auto *ptr_int_type = llvm::cast<llvm::IntegerType>(target_global->getValueType());
  const llvm::APInt key = derive_vm_target_key(function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);

  // Compile-time salt for runtime-context mixing (distinct from key).
  const std::uint64_t raw_salt =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName())) *
      0x9E3779B97F4A7C15ULL;
  const llvm::APInt salt(ptr_int_type->getBitWidth(),
                         raw_salt == 0 ? 0xC6EF3720ULL : raw_salt,
                         /*isSigned=*/false, /*implicitTrunc=*/true);

  bool changed = false;
  std::size_t callsite_index = 0;
  for (const virtualized_call_site &site : binding.call_sites) {
    llvm::CallBase *call = site.call;
    if (call == nullptr) {
      continue;
    }
    llvm::Function *caller = call->getFunction();
    if (caller == nullptr) {
      continue;
    }

    // Per-callee module-level key global (avoids alloca/domination issues
    // when control flattening hoists only leading allocas).
    llvm::GlobalVariable *decode_key_global = get_or_create_vm_decode_key_global(
        *module, ptr_int_type, function.getName(), key);

    // Split the block at the call to create room for the lazy-resolution
    // sentinel check and resolve path.
    llvm::BasicBlock *orig_bb = call->getParent();
    llvm::BasicBlock *call_bb = orig_bb->splitBasicBlock(
        call->getIterator(), (function.getName() + ".obf.call").str());
    orig_bb->getTerminator()->eraseFromParent();

    llvm::BasicBlock *resolve_bb = llvm::BasicBlock::Create(
        module->getContext(), (function.getName() + ".obf.resolve").str(),
        caller, call_bb);

    // --- Entry tail: load slot, compare against sentinel, branch ---
    llvm::IRBuilder<> entry_builder(orig_bb);
    llvm::Value *hidden_token = build_hidden_token_value(
        entry_builder, *caller, (function.getName() + ".obf.call").str(),
        site.hidden_token, mba_depth,
        0x700000ULL + static_cast<std::uint64_t>(callsite_index++));
    auto *encoded_check = entry_builder.CreateLoad(
        ptr_int_type, target_global,
        function.getName() + ".obf.check");
    auto *sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
    auto *is_unresolved = entry_builder.CreateICmpEQ(
        encoded_check, sentinel_const,
        function.getName() + ".obf.unresolved");
    entry_builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

    // --- Resolve block: encode the implementation target and cache it ---
    llvm::IRBuilder<> resolve_builder(resolve_bb);
    auto *target_int = resolve_builder.CreatePtrToInt(
        &implementation_function, ptr_int_type,
        function.getName() + ".obf.real.int");
    llvm::Value *token_int = hidden_token;
    if (token_int->getType() != ptr_int_type) {
      token_int = resolve_builder.CreateZExtOrTrunc(
          token_int, ptr_int_type, function.getName() + ".obf.token.cast");
    }
    const std::string token_name = (function.getName() + ".obf.token").str();
    token_int = mba::entangle_value(
        resolve_builder, token_int,
        mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                             .seed_base = site.hidden_token,
                             .depth = mba_depth},
        0x710000ULL + site.hidden_token, token_name);
    auto *salt_const = llvm::ConstantInt::get(ptr_int_type, salt);
    auto *runtime_key = resolve_builder.CreateXor(
        token_int, salt_const,
        function.getName() + ".obf.rkey");
    auto *mixed = resolve_builder.CreateXor(
        target_int, runtime_key,
        function.getName() + ".obf.mixed");
    auto *unmixed = resolve_builder.CreateXor(
        mixed, runtime_key,
        function.getName() + ".obf.unmixed");
    auto *key_const = llvm::ConstantInt::get(ptr_int_type, key);
    auto *new_encoded = resolve_builder.CreateXor(
        unmixed, key_const,
        function.getName() + ".obf.resolved");
    resolve_builder.CreateStore(new_encoded, target_global);
    resolve_builder.CreateBr(call_bb);

    // --- Call block: merge encoded value, decode, indirect-call ---
    llvm::IRBuilder<> call_builder(call);
    auto *encoded_phi = call_builder.CreatePHI(
        ptr_int_type, 2,
        function.getName() + ".obf.encoded");
    encoded_phi->addIncoming(encoded_check, orig_bb);
    encoded_phi->addIncoming(new_encoded, resolve_bb);

    auto *opaque_key = call_builder.CreateLoad(
        ptr_int_type, decode_key_global,
        function.getName() + ".obf.key");
    llvm::Value *decoded_target =
        mba::create_xor(call_builder, encoded_phi, opaque_key,
                        mba::builder_context{.entropy_anchor = mba::get_or_create_entropy_anchor(*module),
                                             .seed_base = site.hidden_token ^ key.getLimitedValue(),
                                             .depth = mba_depth},
                        0x720000ULL + site.hidden_token,
                        (function.getName() + ".obf.decoded").str());
    llvm::Value *indirect_target = call_builder.CreateIntToPtr(
        decoded_target, call->getCalledOperand()->getType(),
        function.getName() + ".obf.indirect");

    llvm::SmallVector<llvm::Use *, 16> original_uses;
    for (llvm::Use &use : call->uses()) {
      original_uses.push_back(&use);
    }

    llvm::SmallVector<llvm::Value *, 8> arguments;
    arguments.reserve(call->arg_size() + 1);
    for (llvm::Use &argument : call->args()) {
      arguments.push_back(argument.get());
    }
    arguments.push_back(hidden_token);

    auto *rewritten_call = call_builder.CreateCall(
        implementation_function.getFunctionType(), indirect_target, arguments,
        call->getType()->isVoidTy() ? "" : function.getName() + ".obf.callsite");
    rewritten_call->setCallingConv(call->getCallingConv());
    rewritten_call->setAttributes(implementation_function.getAttributes());

    // Decode entangled return value for integer-returning functions.
    llvm::Type *call_ret_type = rewritten_call->getType();
    if (call_ret_type->isIntegerTy()) {
      llvm::IRBuilder<> decode_builder(call);
      llvm::Value *decoded_ret = decode_virtualized_integer_return(
          decode_builder, *caller, function.getName(), rewritten_call,
          hidden_token, site.hidden_token, mba_depth);

      // Patch original uses to consume the decoded value.
      for (llvm::Use *use : original_uses) {
        use->set(decoded_ret);
      }
    } else {
      for (llvm::Use *use : original_uses) {
        use->set(rewritten_call);
      }
    }

    call->eraseFromParent();

    changed = true;
  }

  return changed;
}

bool rewrite_calls_to_virtualized_functions(
    llvm::Module &, const virtualized_function_map &virtualized_functions,
    std::uint32_t mba_depth) {
  bool changed = false;
  for (const auto &entry : virtualized_functions) {
    changed |= rewrite_calls_to_virtualized_function(entry.second, mba_depth);
  }

  return changed;
}

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state> &states,
               const obfuscation_config &config,
               const protection_level *only_level = nullptr) {
  virtualized_function_map virtualized_functions;
  llvm::StringSet<> skip_functions;
  std::uint64_t regional_helper_ordinal = 0;

  for (const function_pipeline_state &state : states) {
    if (state.function == nullptr || state.function->isDeclaration() ||
        !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (only_level && state.report.decision.policy.level != *only_level) {
      continue;
    }

    if (skip_functions.contains(state.function->getName())) {
      continue;
    }

    const llvm::SmallVector<vm_target_candidate, 8> target_candidates =
        discover_vm_targets_for_state(state, skip_functions, regional_helper_ordinal);

    for (const vm_target_candidate &target_candidate : target_candidates) {
      llvm::Function *target_function = target_candidate.function;
      if (target_function == nullptr || target_candidate.state == nullptr) {
        continue;
      }

      const function_pipeline_state target_state{.function = target_function,
                                                 .report = target_candidate.state->report};
      virtualized_function_binding binding =
          prepare_virtualized_function_binding(target_state, config.mba.depth);
      if (binding.implementation_function == nullptr) {
        continue;
      }
      binding.state = target_candidate.state;

      vm::virtualization_options vm_options{.mba_depth = config.mba.depth,
                                            .hidden_token_handshake = true,
                                            .symbol_tag = target_function->getName().str()};
      vm_options.valid_hidden_tokens.push_back(binding.wrapper_token);
      for (const virtualized_call_site &site : binding.call_sites) {
        vm_options.valid_hidden_tokens.push_back(site.hidden_token);
      }

      const vm::virtualization_result result =
          vm::run_virtualization(*binding.implementation_function, vm_options);
      if (result.virtualized) {
        virtualized_functions[target_function->getName()] = std::move(binding);
        skip_functions.insert(target_function->getName());
      }
    }
  }

  return virtualized_functions;
}

bool apply_string_encoding_stage(
    llvm::Module &module,
    const llvm::SmallVectorImpl<function_pipeline_state> &states,
    const obfuscation_config &config,
    const virtualized_function_map *virtualized_functions = nullptr) {
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
    const llvm::StringSet<> *skip_functions = nullptr) {
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
    const llvm::StringSet<> *skip_functions = nullptr) {
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
    const llvm::StringSet<> *skip_functions = nullptr) {
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
        !entry.second.state->report.decision.policy.allow_instruction_substitution) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config,
                                              entry.second.state->report.decision);
    changed |= run_instruction_substitution(*function, options).substitution_count > 0;
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
    const llvm::StringSet<> *skip_functions = nullptr) {
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

llvm::StringSet<> collect_virtualized_function_names(
    const virtualized_function_map &virtualized_functions) {
  llvm::StringSet<> names;
  for (const auto &entry : virtualized_functions) {
    names.insert(entry.getKey());
    if (entry.second.implementation_function != nullptr) {
      names.insert(entry.second.implementation_function->getName());
    }
  }
  return names;
}

void include_vm_parent_functions(llvm::StringSet<> &virtualized_names,
                                 const virtualized_function_map &virtualized_functions) {
  for (const auto &entry : virtualized_functions) {
    const function_pipeline_state *state = entry.second.state;
    if (state == nullptr || state->function == nullptr) {
      continue;
    }

    // Only treat the original parent as VM-owned when the parent itself was
    // virtualized. Regional strong_vm extraction can produce VMized helpers
    // while leaving a readable parent body behind; skipping that parent from
    // later classical hardening leaks the orchestrator structure.
    if (entry.getKey() == state->function->getName()) {
      virtualized_names.insert(state->function->getName());
    }
  }
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

class EntropyInitializationPass
    : public llvm::PassInfoMixin<EntropyInitializationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    if (!apply_entropy_initialization_stage(module)) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class CfgStateCleanupPass : public llvm::PassInfoMixin<CfgStateCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    if (!apply_cfg_state_cleanup_stage(module)) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class ArtifactCleanupPass : public llvm::PassInfoMixin<ArtifactCleanupPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    if (!apply_artifact_cleanup_stage(module, config)) {
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

    const virtualized_function_map virtualized_functions =
        apply_vm_stage(states, config);
    bool changed = !virtualized_functions.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, virtualized_functions,
                                                      config.mba.depth);
    if (!changed) {
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

class opaque_gep_pass : public llvm::PassInfoMixin<opaque_gep_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_opaque_gep_stage(states, config);
    if (!changed) {
      return llvm::PreservedAnalyses::all();
    }

    verify_changed_module(module);
    return llvm::PreservedAnalyses::none();
  }
};

class function_outlining_pass
    : public llvm::PassInfoMixin<function_outlining_pass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &) {
    const obfuscation_config config = load_active_config();
    const llvm::SmallVector<function_pipeline_state, 32> states =
        build_pipeline_state(module, config);

    const bool changed = apply_function_outlining_stage(states, config);
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

    bool changed = apply_entropy_initialization_stage(module);

    // Phase 1: VM for vm-only functions and strong_vm functions on pristine IR.
    constexpr protection_level vm_level = protection_level::vm;
    const virtualized_function_map vm_only = apply_vm_stage(states, config, &vm_level);
    changed |= !vm_only.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, vm_only,
                                                      config.mba.depth);

    constexpr protection_level strong_vm_level = protection_level::strong_vm;
    const virtualized_function_map strong_vm_virtualized =
        apply_vm_stage(states, config, &strong_vm_level);
    changed |= !strong_vm_virtualized.empty();
    changed |= rewrite_calls_to_virtualized_functions(module, strong_vm_virtualized,
                                                      config.mba.depth);

    virtualized_function_map post_vm_virtualized = vm_only;
    for (const auto &entry : strong_vm_virtualized) {
      post_vm_virtualized[entry.getKey()] = entry.second;
    }

    const llvm::SmallVector<function_pipeline_state, 32> post_vm_states =
        build_pipeline_state(module, config);

    // Phase 2: Classical transforms for non-VM functions only.
    changed |= apply_string_encoding_stage(module, post_vm_states, config,
                                           &post_vm_virtualized);
    llvm::StringSet<> all_vm_virtualized = collect_virtualized_function_names(vm_only);
    const llvm::StringSet<> strong_vm_names =
        collect_virtualized_function_names(strong_vm_virtualized);
    for (const auto &entry : strong_vm_names) {
      all_vm_virtualized.insert(entry.getKey());
    }
    include_vm_parent_functions(all_vm_virtualized, strong_vm_virtualized);

    changed |= apply_constant_encoding_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_opaque_gep_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= apply_instruction_substitution_stage(post_vm_states, config,
                                                    &all_vm_virtualized);
    changed |= apply_opaque_predicate_stage(post_vm_states, config,
                                            &all_vm_virtualized);
    const llvm::StringSet<> flattened_functions =
        apply_control_flattening_stage(post_vm_states, config, &all_vm_virtualized);
    changed |= !flattened_functions.empty();
    changed |= apply_cfg_state_cleanup_stage(module);
    changed |= apply_function_outlining_stage(post_vm_states, config,
                                              &all_vm_virtualized);
    changed |= apply_bogus_control_flow_stage(post_vm_states, config,
                                              &all_vm_virtualized);

    // Phase 3: Block split for remaining classical functions only.
    llvm::StringSet<> block_split_skips;
    for (const auto &entry : all_vm_virtualized) {
      block_split_skips.insert(entry.getKey());
    }
    for (const auto &entry : flattened_functions) {
      block_split_skips.insert(entry.getKey());
    }
    changed |= apply_block_split_stage(post_vm_states, config, &block_split_skips);

    // Phase 4: Harden only the generated VM infrastructure for strong_vm.
    changed |= apply_opaque_gep_to_functions(strong_vm_virtualized, config);
    llvm::StringSet<> strong_vm_flattened =
        apply_control_flattening_to_functions(strong_vm_virtualized, config);
    changed |= !strong_vm_flattened.empty();
    changed |= apply_function_outlining_to_functions(strong_vm_virtualized, config);
    changed |=
        apply_instruction_substitution_to_functions(strong_vm_virtualized, config);
    changed |= apply_bogus_control_flow_to_functions(strong_vm_virtualized,
                                                     config);
    changed |= apply_artifact_cleanup_stage(module, config);

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

                  if (name == "obf-entropy-init") {
                    module_pm.addPass(obf::EntropyInitializationPass());
                    return true;
                  }

                  if (name == "obf-cfg-state-cleanup") {
                    module_pm.addPass(obf::CfgStateCleanupPass());
                    return true;
                  }

                  if (name == "obf-artifact-cleanup") {
                    module_pm.addPass(obf::ArtifactCleanupPass());
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

                  if (name == "obf-opaque-gep") {
                    module_pm.addPass(obf::opaque_gep_pass());
                    return true;
                  }

                  if (name == "obf-function-outline") {
                    module_pm.addPass(obf::function_outlining_pass());
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
