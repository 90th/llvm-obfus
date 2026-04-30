#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/analysis/function_features.h"
#include "obf/frontend/annotations.h"
#include "obf/policy/policy_engine.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormatVariadic.h"

#include <algorithm>
#include <optional>
#include <string>

namespace obf {

namespace {

bool has_strong_classical(protection_level level) {
  return level == protection_level::strong ||
         level == protection_level::strong_vm;
}

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

  if (first_sensitive_callee.has_value() &&
      is_top_level_semantic_function(function)) {
    return orchestrator_promotion_reason{
        .callee_name = *first_sensitive_callee,
        .observation = orchestrator_observation_kind::top_level};
  }

  return std::nullopt;
}

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
          llvm::formatv(
              "orchestrator promotion raised to {0} via protected callee {1} ({2})",
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

llvm::cl::opt<std::string> obf_config_path(
    "obf-config",
    llvm::cl::desc("Path to llvm-obfus milestone-zero YAML config"),
    llvm::cl::init(""));

llvm::cl::opt<std::uint64_t> obf_seed_override(
    "obf-seed",
    llvm::cl::desc("Overrides the top-level obfuscation seed"),
    llvm::cl::init(0));

} // namespace

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

std::uint64_t get_obf_seed_override() {
  return obf_seed_override;
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

artifact_cleanup_options
build_artifact_cleanup_options(const obfuscation_config &config) {
  artifact_cleanup_options options;
  options.seed = config.seed;
  return options;
}

block_split_options build_block_split_options(const obfuscation_config &config,
                                              const policy_decision &decision) {
  block_split_options options;
  options.max_splits_per_function = config.block_split.max_splits_per_function;
  options.min_instructions_per_block =
      config.block_split.min_instructions_per_block;

  if (decision.policy.level == protection_level::light) {
    options.max_splits_per_function =
        std::min<std::size_t>(options.max_splits_per_function, 1);
  }

  return options;
}

string_encoding_options
build_string_encoding_options(const obfuscation_config &config) {
  return {.min_string_length = config.string_encoding.min_string_length,
          .max_strings_per_module = config.string_encoding.max_strings_per_module,
          .ctor_priority = 0,
          .prefer_lazy_decode = config.string_encoding.prefer_lazy_decode,
          .allow_ctor_fallback = config.string_encoding.allow_ctor_fallback,
          .strong_vm_allow_global_plaintext = false,
          .strong_vm_allow_lazy_decode = false,
          .strong_vm_allow_ctor_fallback = false,
          .debug_preserve_generated_names =
              config.debug_preserve_generated_names};
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

} // namespace obf
