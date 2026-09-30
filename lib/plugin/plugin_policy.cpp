#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/analysis/function_features.h"
#include "obf/frontend/annotations.h"
#include "obf/policy/policy_engine.h"
#include "obf/support/stable_hash.h"

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
#include <cstdlib>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
namespace obf {

namespace {

std::optional<std::string> get_environment_value(const char* name) {
#if defined(_WIN32)
  char* value = nullptr;
  std::size_t length = 0;
  if (_dupenv_s(&value, &length, name) != 0 || value == nullptr) { return std::nullopt; }

  const std::unique_ptr<char, decltype(&std::free)> owned_value(value, &std::free);
  return std::string(owned_value.get(), length == 0 ? 0 : length - 1);
#else
  if (const char* value = std::getenv(name)) { return std::string(value); }
  return std::nullopt;
#endif
}

constexpr bool function_policy::* kPolicyFlags[] = {
    &function_policy::allow_string_encoding, &function_policy::allow_zero_comparison,
    &function_policy::allow_constant_encoding, &function_policy::allow_instruction_substitution,
    &function_policy::allow_opaque_gep, &function_policy::allow_function_outlining,
    &function_policy::allow_bogus_control_flow, &function_policy::allow_opaque_predicates,
    &function_policy::allow_flattening, &function_policy::allow_split,
    &function_policy::allow_indirect_calls, &function_policy::allow_vm,
    &function_policy::allow_self_checksum};

[[noreturn]] void report_invalid_lto_obligation(const llvm::Function& function,
                                               const llvm::Twine& detail) {
  llvm::report_fatal_error(llvm::Twine("invalid obf.lto contract on function '") +
                          function.getName() + "': " + detail);
}

llvm::StringRef required_lto_attribute(const llvm::Function& function, llvm::StringRef name) {
  const llvm::Attribute attribute = function.getFnAttribute(name);
  if (!attribute.isStringAttribute()) {
    report_invalid_lto_obligation(function, llvm::Twine("missing ") + name);
  }
  return attribute.getValueAsString();
}

std::uint64_t required_lto_integer(const llvm::Function& function, llvm::StringRef name) {
  std::uint64_t value = 0;
  if (required_lto_attribute(function, name).getAsInteger(10, value)) {
    report_invalid_lto_obligation(function, llvm::Twine("invalid ") + name);
  }
  return value;
}

bool is_policy_entry(lto_obligation_role role) {
  return role == lto_obligation_role::protected_entry ||
         role == lto_obligation_role::protected_covered || role == lto_obligation_role::explicit_none ||
         role == lto_obligation_role::raw_entry || role == lto_obligation_role::raw_none;
}

const llvm::Function* resolve_pipeline_configured_function(const llvm::Module& module,
                                                          llvm::StringRef name) {
  if (const llvm::Function* function = resolve_configured_function(module, name)) { return function; }
  for (const llvm::Function& function : module) {
    if (function.isDeclaration() || !function_has_lto_obligation(function)) { continue; }
    const lto_obligation_record record = read_lto_obligation(function);
    if (is_policy_entry(record.role) && record.selector_name == name) { return &function; }
  }
  return nullptr;
}

bool has_strong_classical(protection_level level) {
  return level == protection_level::strong || level == protection_level::strong_vm;
}

bool is_orchestrator_seed_level(protection_level level) {
  return level == protection_level::strong || level == protection_level::vm ||
         level == protection_level::strong_vm;
}

bool is_orchestrator_promoted_level(protection_level level) {
  return level != protection_level::none;
}

bool is_retained_native_none_role(lto_obligation_role role) {
  return role == lto_obligation_role::explicit_none || role == lto_obligation_role::raw_none;
}

// Full LTO can make a previously hidden protected callee visible to a
// retained native boundary. Revisit only the retained native none roles;
// already-protected bodies stay skipped.

bool can_revisit_orchestrator_promotion(const function_pipeline_state& state) {
  return !state.skip_transform_stages ||
         (state.lto.present && is_retained_native_none_role(state.lto.role));
}

bool is_user_pipeline_function(const llvm::Function& function) {
  const llvm::StringRef name = function.getName();
  return !name.starts_with("__obf_") && !name.starts_with("llvm.") &&
         !name.starts_with("rt_core_") && !name.starts_with("_obf_") &&
         !name.contains("ObfEntropy");
}

void resolve_non_generic_configured_names(const llvm::Module& module,
                                         obfuscation_config& config,
                                         bool allow_unresolved) {
  llvm::SmallPtrSet<const llvm::Function*, 8> selected;
  const auto resolve_name = [&](std::string& name) {
    const llvm::Function* function = resolve_pipeline_configured_function(module, name);
    if (function == nullptr) {
      if (allow_unresolved) { return false; }
      llvm::report_fatal_error(llvm::Twine("config error: non-generic frontend configured function '") +
                              name + "' is not a defined function");
    }
    if (!selected.insert(function).second) {
      llvm::report_fatal_error(llvm::Twine("config error: non-generic frontend configured function '") +
                              name + "' resolves to a function already selected by another target or override");
    }
    if (function->getName().find_first_of("*?") != llvm::StringRef::npos) {
      llvm::report_fatal_error(llvm::Twine("config error: configured alias '") + name +
                              "' resolves to a function whose name is not exact");
    }
    name = function->getName().str();
    return true;
  };

  std::erase_if(config.targets, [&](target_rule& rule) { return !resolve_name(rule.match); });
  std::erase_if(config.overrides,
                [&](function_override& override) { return !resolve_name(override.name); });
}

bool is_top_level_semantic_function(const llvm::Function& function) {
  return function.getName() == "main";
}

enum class orchestrator_observation_kind {
  top_level,
  control_flow,
  call_argument,
  return_value,
  memory_sink,
};

llvm::StringRef describe_orchestrator_observation(orchestrator_observation_kind kind) {
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

void append_policy_detail(std::string& detail, llvm::StringRef suffix) {
  if (!detail.empty()) { detail += "; "; }

  detail += suffix.str();
}

function_policy build_orchestrator_promotion_policy(const function_features& features) {
  function_policy policy = make_function_policy(protection_level::strong);
  if (!(features.has_exception_edges || features.has_inline_asm)) { return policy; }

  policy = make_function_policy(protection_level::light);
  policy.allow_instruction_substitution = false;
  policy.allow_function_outlining = false;
  policy.allow_bogus_control_flow = false;
  policy.allow_opaque_predicates = false;
  policy.allow_flattening = false;
  policy.allow_split = false;
  policy.allow_indirect_calls = false;
  policy.allow_vm = false;
  policy.allow_self_checksum = false;
  return policy;
}

std::optional<orchestrator_observation_kind>
find_protected_result_observation(const llvm::Value& root, const llvm::Function& owner) {
  llvm::SmallVector<const llvm::Value*, 16> worklist;
  llvm::SmallPtrSet<const llvm::Value*, 32> visited;
  worklist.push_back(&root);

  while (!worklist.empty()) {
    const llvm::Value* value = worklist.pop_back_val();
    if (!visited.insert(value).second) { continue; }

    for (const llvm::User* user : value->users()) {
      const auto* instruction = llvm::dyn_cast<llvm::Instruction>(user);
      if (instruction == nullptr || instruction->getFunction() != &owner) { continue; }

      if (const auto* branch = llvm::dyn_cast<llvm::BranchInst>(instruction)) {
        if (branch->isConditional()) { return orchestrator_observation_kind::control_flow; }
      }

      if (llvm::isa<llvm::SwitchInst>(instruction) || llvm::isa<llvm::SelectInst>(instruction) ||
          llvm::isa<llvm::ICmpInst>(instruction) || llvm::isa<llvm::FCmpInst>(instruction)) {
        return orchestrator_observation_kind::control_flow;
      }

      if (llvm::isa<llvm::ReturnInst>(instruction)) {
        return orchestrator_observation_kind::return_value;
      }

      if (const auto* store = llvm::dyn_cast<llvm::StoreInst>(instruction)) {
        if (store->getValueOperand() == value) {
          const llvm::Value* pointer =
              llvm::getUnderlyingObject(store->getPointerOperand()->stripPointerCasts());
          if (!llvm::isa<llvm::AllocaInst>(pointer)) {
            return orchestrator_observation_kind::memory_sink;
          }
          worklist.push_back(pointer);
          continue;
        }
      }

      if (const auto* call = llvm::dyn_cast<llvm::CallBase>(instruction)) {
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
  orchestrator_observation_kind observation = orchestrator_observation_kind::top_level;
};

std::optional<orchestrator_promotion_reason>
find_orchestrator_promotion_reason(const llvm::Function& function,
                                   const llvm::StringSet<>& sensitive_functions) {
  std::optional<llvm::StringRef> first_sensitive_callee;

  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call == nullptr) { continue; }

      const llvm::Value* called_operand = call->getCalledOperand()->stripPointerCasts();
      const auto* callee = llvm::dyn_cast<llvm::Function>(called_operand);
      if (callee == nullptr || !sensitive_functions.contains(callee->getName())) { continue; }

      if (!first_sensitive_callee.has_value()) { first_sensitive_callee = callee->getName(); }

      if (is_top_level_semantic_function(function)) {
        return orchestrator_promotion_reason{.callee_name = callee->getName(),
                                             .observation =
                                                 orchestrator_observation_kind::top_level};
      }

      if (!call->getType()->isVoidTy()) {
        if (const auto observation = find_protected_result_observation(*call, function)) {
          return orchestrator_promotion_reason{.callee_name = callee->getName(),
                                               .observation = *observation};
        }
      }
    }
  }

  if (first_sensitive_callee.has_value() && is_top_level_semantic_function(function)) {
    return orchestrator_promotion_reason{.callee_name = *first_sensitive_callee,
                                         .observation = orchestrator_observation_kind::top_level};
  }

  return std::nullopt;
}

void apply_orchestrator_policy_promotions(llvm::SmallVectorImpl<function_pipeline_state>& states) {
  llvm::StringSet<> sensitive_functions;
  for (const function_pipeline_state& state : states) {
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

    for (function_pipeline_state& state : states) {
      llvm::Function* function = state.function;
      if (function == nullptr || function->isDeclaration() ||
          !can_revisit_orchestrator_promotion(state) || !is_user_pipeline_function(*function) ||
          has_strong_classical(state.report.decision.policy.level)) {
        continue;
      }

      const auto reason = find_orchestrator_promotion_reason(*function, sensitive_functions);
      if (!reason.has_value()) { continue; }

      const function_policy promoted_policy =
          build_orchestrator_promotion_policy(state.report.features);
      if (promoted_policy.level == state.report.decision.policy.level) { continue; }

      state.report.decision.policy = promoted_policy;
      append_policy_detail(
          state.report.decision.detail,
          llvm::formatv("orchestrator promotion raised to {0} via protected callee {1} ({2})",
                        to_string(promoted_policy.level),
                        reason->callee_name,
                        describe_orchestrator_observation(reason->observation))
              .str());
      if (state.lto.present && is_retained_native_none_role(state.lto.role) &&
          is_orchestrator_promoted_level(promoted_policy.level)) {
        state.skip_transform_stages = false;
      }
      if (is_orchestrator_promoted_level(promoted_policy.level)) {
        sensitive_functions.insert(function->getName());
      }
      changed = true;
    }
  }
}

#if !defined(_WIN32)
llvm::cl::opt<std::string>
    obf_config_path("obf-config",
                    llvm::cl::desc("Path to llvm-obfus milestone-zero YAML config"),
                    llvm::cl::init(""));

llvm::cl::opt<bool>
    obf_enable("obf-enable", llvm::cl::desc("Enable obfuscation pipeline"), llvm::cl::init(false));

llvm::cl::opt<std::uint64_t> obf_seed_override(
    "obf-seed", llvm::cl::desc("Overrides the top-level obfuscation seed"), llvm::cl::init(0));
#endif

}  // namespace

obf_lto_mode get_active_lto_mode() {
  const std::optional<std::string> mode = get_environment_value("OBF_LTO_MODE");
  if (!mode.has_value() || mode->empty()) { return obf_lto_mode::none; }
  if (*mode == "full") { return obf_lto_mode::full; }
  if (*mode == "thin") { return obf_lto_mode::thin; }
  llvm::report_fatal_error("OBF_LTO_MODE must be full or thin");
}

std::uint64_t compute_lto_config_identity(const obfuscation_config& config) {
  // This is a deterministic compatibility identity, not an authentication key.
  // Conservatively require the effective policy/options that produced the IR.
  std::uint64_t identity = stable_hash_string(summarize_config(config), 0x6f62662e6c746f01ULL);
  identity = mix_seed(identity, config.string_encoding.enable_ephemeral_slots);
  identity = mix_seed(identity, config.self_checksum.enabled);
  identity = mix_seed(identity, config.self_checksum.window_size);
  identity = mix_seed(identity, config.self_checksum.max_sites);
  identity = mix_seed(identity, config.self_checksum.seed);
  return mix_seed(identity, get_obf_seed_override());
}

bool function_has_lto_obligation(const llvm::Function& function) {
  return function.hasFnAttribute("obf.lto.role");
}

lto_obligation_record read_lto_obligation(const llvm::Function& function) {
  lto_obligation_record record;
  if (!function_has_lto_obligation(function)) { return record; }
  record.present = true;
  const std::uint64_t role = required_lto_integer(function, "obf.lto.role");
  const std::uint64_t source = required_lto_integer(function, "obf.lto.source");
  if (role == 0 || role > static_cast<unsigned>(lto_obligation_role::raw_none) ||
      source > static_cast<unsigned>(policy_source::explicit_override)) {
    report_invalid_lto_obligation(function, "invalid role or policy source");
  }
  record.role = static_cast<lto_obligation_role>(role);
  record.source = static_cast<policy_source>(source);
  const auto level = parse_protection_level(required_lto_attribute(function, "obf.lto.level"));
  if (!level.has_value()) { report_invalid_lto_obligation(function, "invalid protection level"); }
  record.policy.level = *level;
  const std::uint64_t mask = required_lto_integer(function, "obf.lto.policy.mask");
  if (mask >> std::size(kPolicyFlags)) {
    report_invalid_lto_obligation(function, "invalid policy options");
  }
  for (unsigned index = 0; index < std::size(kPolicyFlags); ++index) {
    record.policy.*kPolicyFlags[index] = (mask & (1ULL << index)) != 0;
  }
  record.entry_identity = required_lto_integer(function, "obf.lto.entry.id");
  record.config_identity = required_lto_integer(function, "obf.lto.config.id");
  record.decision_seed = required_lto_integer(function, "obf.lto.decision.seed");
  record.selector_name = required_lto_attribute(function, "obf.lto.selector").str();
  record.annotation = required_lto_attribute(function, "obf.lto.annotation").str();
  record.selection_detail = required_lto_attribute(function, "obf.lto.selection").str();
  record.requires_finalization = required_lto_integer(function, "obf.lto.finalize") != 0;
  record.pinned_noinline = required_lto_integer(function, "obf.lto.pin.noinline") != 0;
  record.uses_target_cache = required_lto_integer(function, "obf.lto.uses.target_cache") != 0;
  record.uses_shared_seed_resolver =
      required_lto_integer(function, "obf.lto.uses.shared_seed_resolver") != 0;
  return record;
}

void apply_lto_obligation(llvm::Function& function, const lto_obligation_record& record) {
  function.addFnAttr("obf.lto.role", std::to_string(static_cast<unsigned>(record.role)));
  function.addFnAttr("obf.lto.source", std::to_string(static_cast<unsigned>(record.source)));
  const std::string_view level = to_string(record.policy.level);
  function.addFnAttr("obf.lto.level", llvm::StringRef(level.data(), level.size()));
  std::uint64_t mask = 0;
  for (unsigned index = 0; index < std::size(kPolicyFlags); ++index) {
    if (record.policy.*kPolicyFlags[index]) { mask |= 1ULL << index; }
  }
  function.addFnAttr("obf.lto.policy.mask", std::to_string(mask));
  function.addFnAttr("obf.lto.entry.id", std::to_string(record.entry_identity));
  function.addFnAttr("obf.lto.config.id", std::to_string(record.config_identity));
  function.addFnAttr("obf.lto.decision.seed", std::to_string(record.decision_seed));
  function.addFnAttr("obf.lto.selector", record.selector_name);
  function.addFnAttr("obf.lto.annotation", record.annotation);
  function.addFnAttr("obf.lto.selection", record.selection_detail);
  function.addFnAttr("obf.lto.finalize", record.requires_finalization ? "1" : "0");
  function.addFnAttr("obf.lto.pin.noinline", record.pinned_noinline ? "1" : "0");
  function.addFnAttr("obf.lto.uses.target_cache", record.uses_target_cache ? "1" : "0");
  function.addFnAttr("obf.lto.uses.shared_seed_resolver", record.uses_shared_seed_resolver ? "1" : "0");
}

void clear_lto_obligation(llvm::Function& function) {
  llvm::SmallVector<llvm::StringRef, 16> names;
  for (llvm::Attribute attribute : function.getAttributes().getFnAttrs()) {
    if (attribute.isStringAttribute() && attribute.getKindAsString().starts_with("obf.lto.")) {
      names.push_back(attribute.getKindAsString());
    }
  }
  for (llvm::StringRef name : names) { function.removeFnAttr(name); }
}

bool is_obfuscation_enabled() {
  if (const std::optional<std::string> env = get_environment_value("OBF_ENABLE")) {
    if (llvm::StringRef(*env) == "1" || llvm::StringRef(*env) == "true") { return true; }
  }
  if (const std::optional<std::string> env = get_environment_value("OBF_CONFIG")) {
    if (llvm::StringRef(*env) != "") { return true; }
  }
#if !defined(_WIN32)
  return obf_enable || !obf_config_path.empty();
#else
  return false;
#endif
}

std::uint32_t effective_vm_mba_depth(const obfuscation_config& config) {
  return config.vm.max_mba_depth ? std::min(config.mba.depth, *config.vm.max_mba_depth)
                                 : config.mba.depth;
}

obfuscation_config load_active_config() {
  static std::optional<obfuscation_config> cached_config;
  if (cached_config.has_value()) { return *cached_config; }

  std::string config_path;
#if !defined(_WIN32)
  config_path = obf_config_path.getValue();
#endif
  if (config_path.empty()) {
    if (const std::optional<std::string> env = get_environment_value("OBF_CONFIG")) {
      config_path = *env;
    }
  }

  obfuscation_config config;
  if (config_path.empty()) {
    config = {};
  } else {
    llvm::Expected<obfuscation_config> loaded_config = load_config_from_file(config_path);
    if (!loaded_config) {
      const std::string error_message = llvm::toString(loaded_config.takeError());
      llvm::report_fatal_error(llvm::StringRef(error_message));
    }

    config = *loaded_config;
  }

  std::uint64_t effective_seed = 0;
#if !defined(_WIN32)
  effective_seed = obf_seed_override;
#endif
  if (effective_seed == 0) {
    if (const std::optional<std::string> env_seed = get_environment_value("OBF_SEED")) {
      std::uint64_t parsed_seed = 0;
      if (!llvm::StringRef(*env_seed).getAsInteger(10, parsed_seed) && parsed_seed != 0) {
        effective_seed = parsed_seed;
      }
    }
  }
  if (effective_seed != 0) { config.seed = effective_seed; }
  validate_effective_config(config);
  cached_config = config;
  return *cached_config;
}

std::uint64_t get_obf_seed_override() {
#if !defined(_WIN32)
  if (obf_seed_override != 0) { return obf_seed_override; }
#endif
  if (const std::optional<std::string> env_seed = get_environment_value("OBF_SEED")) {
    std::uint64_t parsed_seed = 0;
    if (!llvm::StringRef(*env_seed).getAsInteger(10, parsed_seed)) { return parsed_seed; }
  }
  return 0;
}

llvm::SmallVector<function_pipeline_state, 32>
build_lto_pipeline_state(llvm::Module& module, const obfuscation_config& config,
                         bool allow_unresolved_selectors) {
  if (!allow_unresolved_selectors &&
      llvm::none_of(module, [](const llvm::Function& function) {
        return function_has_lto_obligation(function);
      })) {
    validate_effective_config(config, module);
  }
  validate_effective_config(config);
  std::optional<obfuscation_config> resolved_config;
  if (config.frontend != frontend_kind::generic) {
    resolved_config.emplace(config);
    resolve_non_generic_configured_names(module, *resolved_config, allow_unresolved_selectors);
  }

  const obfuscation_config& policy_config = resolved_config.has_value() ? *resolved_config : config;
  const function_annotation_map annotations = config.frontend == frontend_kind::generic
                                                  ? collect_function_annotations(module)
                                                  : function_annotation_map{};
  const std::uint64_t config_identity = compute_lto_config_identity(config);
  llvm::SmallVector<function_pipeline_state, 32> states;
  states.reserve(module.size());

  for (llvm::Function& function : module) {
    function_pipeline_state state;
    state.function = &function;
    state.report.features = collect_function_features(function);
    state.lto = read_lto_obligation(function);
    if (state.lto.present) {
      if (state.lto.config_identity != config_identity) {
        llvm::report_fatal_error(llvm::Twine("incompatible LTO obfuscation config/seed for '") +
                                state.lto.selector_name + "'; rebuild its pre-link bitcode");
      }
      state.skip_transform_stages = state.lto.role != lto_obligation_role::raw_entry;
      state.report.annotation = state.lto.annotation;
      state.report.decision.seed = state.lto.decision_seed;
      state.report.decision.source = state.lto.source;
      state.report.decision.detail = state.lto.selection_detail;
      state.report.decision.policy = is_policy_entry(state.lto.role)
                                         ? state.lto.policy
                                         : make_function_policy(protection_level::none);
    } else {
      if (const std::string* annotation =
              find_function_annotation(annotations, function.getName())) {
        state.report.annotation = *annotation;
      }
      state.report.decision = select_policy(
          module, state.report.features, policy_config, state.report.annotation);
    }
    states.push_back(std::move(state));
  }

  if (config.frontend == frontend_kind::generic) { apply_orchestrator_policy_promotions(states); }
  return states;
}

llvm::SmallVector<function_pipeline_state, 32>
build_pipeline_state(llvm::Module& module, const obfuscation_config& config) {
  return build_lto_pipeline_state(module, config, get_active_lto_mode() != obf_lto_mode::none);
}

artifact_cleanup_options build_artifact_cleanup_options(const obfuscation_config& config) {
  artifact_cleanup_options options;
  options.seed = config.seed;
  options.strip_release_markers = config.security.strip_release_markers;
  return options;
}

block_split_options build_block_split_options(const obfuscation_config& config,
                                              const policy_decision& decision) {
  block_split_options options;
  options.max_splits_per_function = config.block_split.max_splits_per_function;
  options.min_instructions_per_block = config.block_split.min_instructions_per_block;

  if (decision.policy.level == protection_level::light) {
    options.max_splits_per_function = std::min<std::size_t>(options.max_splits_per_function, 1);
  }

  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;

  return options;
}

string_encoding_options build_string_encoding_options(const obfuscation_config& config) {
  return {.min_string_length = config.string_encoding.min_string_length,
          .max_strings_per_module = config.frontend == frontend_kind::tinygo
                                        ? 0
                                        : config.string_encoding.max_strings_per_module,
          .ctor_priority = 0,
          .prefer_lazy_decode = config.string_encoding.prefer_lazy_decode,
          .allow_ctor_fallback = config.string_encoding.allow_ctor_fallback,
          .authenticated_mode = config.string_encoding.authenticated_mode,
          .strong_vm_allow_global_plaintext = false,
          .strong_vm_allow_lazy_decode = false,
          .strong_vm_allow_ctor_fallback = false,
          .enable_ephemeral_slots = config.string_encoding.enable_ephemeral_slots,
          .debug_preserve_generated_names = config.debug_preserve_generated_names};
}

constant_encoding_options build_constant_encoding_options(const obfuscation_config& config,
                                                          const policy_decision& decision) {
  constant_encoding_options options;
  options.mode = config.constant_encoding.mode;
  options.max_constants_per_function = config.constant_encoding.max_constants_per_function;
  options.min_bit_width = config.constant_encoding.min_bit_width;

  if (decision.policy.level == protection_level::light) {
    options.max_constants_per_function =
        std::min<std::size_t>(options.max_constants_per_function, 2);
  }

  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  return options;
}

zero_comparison_options build_zero_comparison_options(const obfuscation_config& config,
                                                      const policy_decision& decision) {
  zero_comparison_options options;
  options.max_sites_per_function = config.zero_comparison.max_sites_per_function;
  options.max_unroll_bytes = config.zero_comparison.max_unroll_bytes;
  options.transform_string_comparisons = config.zero_comparison.transform_string_comparisons;
  options.transform_integer_comparisons = config.zero_comparison.transform_integer_comparisons;
  options.seed = decision.seed;
  return options;
}

control_flattening_options build_control_flattening_options(const obfuscation_config& config,
                                                            const policy_decision& decision) {
  control_flattening_options options;
  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.seed = decision.seed;
  if (has_strong_classical(decision.policy.level)) {
    options.max_blocks = 20;
    options.max_instructions = 192;
    options.max_decoy_states = 3;
  }

  return options;
}

indirect_dispatch_options build_indirect_dispatch_options(const obfuscation_config& config,
                                                          const policy_decision& decision) {
  indirect_dispatch_options options;
  options.enabled = config.indirect_dispatch.enabled;
  options.max_sites_per_function = config.indirect_dispatch.max_sites_per_function;
  options.max_switch_targets = config.indirect_dispatch.max_switch_targets;
  options.target_vm_dispatchers = config.indirect_dispatch.target_vm_dispatchers;
  options.target_flattened_headers = config.indirect_dispatch.target_flattened_headers;
  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.seed = decision.seed;
  return options;
}

instruction_substitution_options
build_instruction_substitution_options(const obfuscation_config& config,
                                       const policy_decision& decision) {
  instruction_substitution_options options;
  if (has_strong_classical(decision.policy.level)) {
    options.max_substitutions_per_function = 6;
  } else {
    options.max_substitutions_per_function = 2;
  }

  options.seed = decision.seed;
  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.max_padded_sites = has_strong_classical(decision.policy.level) ? 2 : 0;

  return options;
}

opaque_gep_options build_opaque_gep_options(const obfuscation_config& config,
                                            const policy_decision& decision) {
  opaque_gep_options options;
  options.seed = decision.seed;
  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  return options;
}

function_outlining_options build_function_outlining_options(const obfuscation_config& config,
                                                            const policy_decision& decision) {
  function_outlining_options options;
  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.seed = decision.seed;
  if (has_strong_classical(decision.policy.level)) {
    options.min_cluster_size = 2;
    options.max_cluster_size = 4;
  }

  return options;
}

bogus_control_flow_options build_bogus_control_flow_options(const obfuscation_config& config,
                                                            const policy_decision& decision) {
  bogus_control_flow_options options;
  if (has_strong_classical(decision.policy.level)) { options.max_insertions_per_function = 2; }

  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.seed = decision.seed;
  return options;
}

opaque_predicate_options build_opaque_predicate_options(const obfuscation_config& config,
                                                        const policy_decision& decision) {
  opaque_predicate_options options;
  if (has_strong_classical(decision.policy.level)) { options.max_insertions_per_function = 2; }

  options.mba_depth = config.mba.depth;
  options.mba_max_ir_instructions = config.mba.max_ir_instructions;
  options.mba_enable_polynomial = config.mba.enable_polynomial;
  options.mba_enable_multiplication = config.mba.enable_multiplication;
  options.seed = decision.seed;
  return options;
}

}  // namespace obf
