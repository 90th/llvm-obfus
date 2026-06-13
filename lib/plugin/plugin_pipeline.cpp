#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/transforms/entropy_initialization.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <optional>
#include <string>
#include <vector>

namespace obf {

namespace {

bool should_skip_function(const function_pipeline_state& state,
                          const llvm::StringSet<>* skip_functions) {
  if (state.function == nullptr || state.function->isDeclaration()) { return true; }

  return skip_functions != nullptr && skip_functions->contains(state.function->getName());
}

[[noreturn]] void report_security_gate_failure(llvm::StringRef detail) {
  std::string message = "security gate failure: ";
  message += detail.str();
  llvm::report_fatal_error(llvm::StringRef(message));
}

[[noreturn]] void report_strong_vm_invariant_violation(llvm::StringRef detail) {
  std::string message = "strong_vm invariant violation: ";
  message += detail.str();
  llvm::report_fatal_error(llvm::StringRef(message));
}

bool is_strong_vm_state(const function_pipeline_state& state) {
  return state.function != nullptr && !state.function->isDeclaration() &&
         state.report.decision.policy.level == protection_level::strong_vm;
}

bool binding_belongs_to_state(const virtualized_function_binding& binding,
                              const function_pipeline_state& state) {
  if (binding.state == &state) { return true; }

  return binding.state != nullptr && binding.state->function != nullptr &&
         state.function != nullptr &&
         binding.state->function->getName() == state.function->getName();
}

bool has_virtualized_binding_for_state(const virtualized_function_map& virtualized_functions,
                                       const function_pipeline_state& state) {
  for (const auto& entry : virtualized_functions) {
    if (binding_belongs_to_state(entry.second, state)) { return true; }
  }

  return false;
}

llvm::StringRef classify_vm_candidate_reason_tag(llvm::StringRef reason) {
  if (reason.contains("varargs unsupported")) { return "varargs_unsupported"; }
  if (reason.contains("non-integral pointer space unsupported")) {
    return "non_integral_pointer_unsupported";
  }
  if (reason.contains("exceptions unsupported")) { return "exceptions_unsupported"; }
  if (reason.contains("eh pad unsupported")) { return "eh_pad_unsupported"; }
  if (reason.contains("inline asm unsupported")) { return "inline_asm_unsupported"; }
  if (reason.contains("no whole-function or regional VM target")) { return "no_vm_target"; }
  if (reason.contains("unsupported")) { return "unsupported_shape"; }
  return "unclassified";
}

llvm::StringRef vm_candidate_reason_remediation(llvm::StringRef reason_tag) {
  if (reason_tag == "varargs_unsupported") {
    return "remove varargs or lower protection level for this function";
  }
  if (reason_tag == "non_integral_pointer_unsupported") {
    return "use an integral function pointer address space or exclude function from vm";
  }
  if (reason_tag == "exceptions_unsupported" || reason_tag == "eh_pad_unsupported") {
    return "exclude EH-heavy function from strong_vm or refactor EH boundary";
  }
  if (reason_tag == "inline_asm_unsupported") {
    return "remove inline asm or exclude function from strong_vm";
  }
  if (reason_tag == "no_vm_target") {
    return "ensure function has a whole-function or regional VM target";
  }
  return "review candidate analysis detail and adjust function policy";
}

void enforce_strong_vm_virtualization_gate(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const virtualized_function_map& virtualized_functions) {
  for (const function_pipeline_state& state : states) {
    if (!is_strong_vm_state(state) || !state.report.decision.policy.allow_vm ||
        has_virtualized_binding_for_state(virtualized_functions, state)) {
      continue;
    }

    const vm::candidate_result result = vm::analyze_candidate(*state.function);
    std::string detail = "function ";
    detail += state.function->getName().str();
    detail += " was not virtualized; policy_source=";
    detail += std::string(to_string(state.report.decision.source));
    detail += "; policy_detail=";
    detail += state.report.decision.detail;
    detail += "; reason=";
    const llvm::StringRef reason =
        result.detail.empty() ? llvm::StringRef("no whole-function or regional VM target")
                              : llvm::StringRef(result.detail);
    detail += reason.str();
    const llvm::StringRef reason_tag = classify_vm_candidate_reason_tag(reason);
    detail += "; reason_tag=";
    detail += reason_tag.str();
    detail += "; remediation=";
    detail += vm_candidate_reason_remediation(reason_tag).str();
    report_strong_vm_invariant_violation(detail);
  }
}

std::string join_owner_names(const std::vector<std::string>& owners) {
  if (owners.empty()) { return "unknown"; }

  std::string joined;
  for (const std::string& owner : owners) {
    if (!joined.empty()) { joined += ","; }
    joined += owner;
  }
  return joined;
}

void enforce_strong_vm_string_gate(llvm::Module& module,
                                   const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                   const virtualized_function_map& virtualized_functions,
                                   const obfuscation_config& config) {
  llvm::StringMap<std::uint64_t> protected_functions = build_function_seed_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  llvm::StringMap<protection_level> protected_levels = build_function_level_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  append_virtualized_function_seeds(
      protected_functions, &virtualized_functions, [](const function_policy& policy) {
        return policy.allow_string_encoding;
      });
  append_virtualized_function_levels(
      protected_levels, &virtualized_functions, [](const function_policy& policy) {
        return policy.allow_string_encoding;
      });

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = analyze_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }
        return iterator->second;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = protected_levels.find(function_name);
        if (iterator == protected_levels.end()) { return std::nullopt; }
        return iterator->second;
      },
      options,
      config.seed);

  for (const string_encoding_result& result : results) {
    if (!result.has_strong_vm_use) { continue; }

    const bool leaves_plaintext = !result.applied;
    const bool uses_global_fallback =
        result.applied && result.mode != string_encoding_mode::inline_stack_decode &&
        result.key_schedule != string_key_schedule_kind::blake2s_keyed_auth_v3;
    if (!leaves_plaintext && !uses_global_fallback) { continue; }

    std::string detail = "string ";
    detail += result.global_name.empty() ? "<unknown>" : result.global_name;
    detail += " would remain plaintext; owner=";
    detail += join_owner_names(result.strong_vm_owner_names);
    detail += "; mode=";
    detail += std::string(to_string(result.mode));
    detail += "; fallback_reason=";
    detail += result.fallback_reason.empty() ? "none" : result.fallback_reason;
    detail += "; detail=";
    detail += result.detail.empty() ? "unknown" : result.detail;
    report_strong_vm_invariant_violation(detail);
  }
}

std::string
describe_strong_vm_binding_name(const llvm::StringMapEntry<virtualized_function_binding>& entry,
                                const virtualized_function_binding& binding) {
  if (binding.interface_function != nullptr) { return binding.interface_function->getName().str(); }

  return entry.getKey().str();
}

bool is_strong_vm_binding(const virtualized_function_binding& binding) {
  return binding.state != nullptr &&
         binding.state->report.decision.policy.level == protection_level::strong_vm;
}

std::string describe_attribute(llvm::Attribute attribute) { return attribute.getAsString(); }

bool is_unsafe_strong_vm_function_attribute(llvm::Attribute attribute) {
  const std::string text = describe_attribute(attribute);
  return text == "mustprogress" || text == "nofree" || text == "norecurse" || text == "nosync" ||
         text == "willreturn" || text == "readnone" || text == "readonly" ||
         llvm::StringRef(text).starts_with("memory(");
}

void enforce_strong_vm_function_attributes(llvm::Function* function,
                                           llvm::StringRef target_name,
                                           llvm::StringRef role) {
  if (function == nullptr) { return; }

  for (llvm::Attribute attribute : function->getAttributes().getFnAttrs()) {
    if (!is_unsafe_strong_vm_function_attribute(attribute)) { continue; }

    std::string detail = "function ";
    detail += target_name.str();
    detail += ' ';
    detail += role.str();
    detail += " retained unsafe attribute ";
    detail += describe_attribute(attribute);
    report_strong_vm_invariant_violation(detail);
  }
}

void enforce_strong_vm_implementation_gate(const virtualized_function_map& virtualized_functions) {
  for (const auto& entry : virtualized_functions) {
    const virtualized_function_binding& binding = entry.second;
    if (!is_strong_vm_binding(binding)) { continue; }

    const std::string name = describe_strong_vm_binding_name(entry, binding);
    if (binding.implementation_function == nullptr) {
      report_strong_vm_invariant_violation("function " + name + " has no VM implementation");
    }

    if (!binding.implementation_function->hasLocalLinkage()) {
      report_strong_vm_invariant_violation("function " + name +
                                           " VM implementation has public linkage");
    }

    enforce_strong_vm_function_attributes(binding.interface_function, name, "wrapper");
    enforce_strong_vm_function_attributes(
        binding.implementation_function, name, "VM implementation");
  }
}

bool function_calls_named(llvm::Function* function, llvm::StringRef callee_name) {
  if (function == nullptr || function->isDeclaration()) { return false; }

  for (llvm::BasicBlock& block : *function) {
    for (llvm::Instruction& instruction : block) {
      auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call == nullptr) { continue; }
      const llvm::Function* callee = call->getCalledFunction();
      if (callee != nullptr && callee->getName() == callee_name) { return true; }
    }
  }

  return false;
}

void enforce_strong_vm_shared_seed_gate(
    llvm::Module& module,
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const virtualized_function_map& virtualized_functions) {
  for (const function_pipeline_state& state : states) {
    if (!is_strong_vm_state(state)) { continue; }

    const std::string original_case_name = ("__obf_vm_seedcase_" + state.function->getName()).str();
    if (module.getFunction(original_case_name) != nullptr) {
      report_strong_vm_invariant_violation(state.function->getName().str() +
                                           " used shared seed resolver");
    }
  }

  for (const auto& entry : virtualized_functions) {
    const virtualized_function_binding& binding = entry.second;
    if (binding.state == nullptr ||
        binding.state->report.decision.policy.level != protection_level::strong_vm) {
      continue;
    }

    const llvm::Function* interface_function = binding.interface_function;
    if (interface_function != nullptr) {
      const std::string case_name = ("__obf_vm_seedcase_" + interface_function->getName()).str();
      if (module.getFunction(case_name) != nullptr) {
        report_strong_vm_invariant_violation(interface_function->getName().str() +
                                             " used shared seed resolver");
      }
    }

    if (!binding.seed_case_function_name.empty() &&
        module.getFunction(binding.seed_case_function_name) != nullptr) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(name.str() + " used shared seed resolver");
    }

    if (binding.uses_shared_seed_resolver) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(name.str() + " used shared seed resolver");
    }

    if (function_calls_named(binding.interface_function, "__obf_vm_seed_resolve") ||
        function_calls_named(binding.implementation_function, "__obf_vm_seed_resolve")) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(name.str() + " used shared seed resolver");
    }
  }
}

void enforce_strong_vm_target_cache_gate(
    llvm::Module& module,
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const virtualized_function_map& virtualized_functions) {
  for (const function_pipeline_state& state : states) {
    if (!is_strong_vm_state(state)) { continue; }

    const std::string target_name = ("__obf_vm_target_" + state.function->getName()).str();
    if (module.getNamedGlobal(target_name) != nullptr) {
      report_strong_vm_invariant_violation(state.function->getName().str() +
                                           " emitted target-cache resolver");
    }
  }

  for (const auto& entry : virtualized_functions) {
    const virtualized_function_binding& binding = entry.second;
    if (binding.state == nullptr ||
        binding.state->report.decision.policy.level != protection_level::strong_vm ||
        binding.interface_function == nullptr) {
      continue;
    }

    const std::string target_name =
        ("__obf_vm_target_" + binding.interface_function->getName()).str();
    if (module.getNamedGlobal(target_name) != nullptr ||
        (!binding.target_cache_global_name.empty() &&
         module.getNamedGlobal(binding.target_cache_global_name) != nullptr)) {
      report_strong_vm_invariant_violation(binding.interface_function->getName().str() +
                                           " emitted target-cache resolver");
    }

    if (binding.uses_target_cache) {
      report_strong_vm_invariant_violation(binding.interface_function->getName().str() +
                                           " emitted target-cache resolver");
    }
  }
}

bool is_obfuscator_internal_symbol_name(llvm::StringRef name) {
  constexpr llvm::StringLiteral prefixes[] = {"__obf_vm_impl_",
                                              "__obf_vm_region_",
                                              "__obf_vm_seedcase_",
                                              "__obf_vm_seed_resolve",
                                              "__obf_vm_target_",
                                              "__obf_vm_targetseed_",
                                              "__obf_vm_key_",
                                              "__obf_vm_retkey_",
                                              "__obf_vm_",
                                              "__obf_str_",
                                              "__obf_decode_",
                                              "__obf_cached_",
                                              "__obf_decoded_",
                                              "__obf_lazy_",
                                              "__obf_desc_",
                                              "__obf_family_",
                                              "__obf_entropy_thunk_"};
  for (llvm::StringRef prefix : prefixes) {
    if (name.starts_with(prefix)) { return true; }
  }

  return false;
}

bool has_public_obfuscator_linkage(const llvm::GlobalValue& value) {
  return is_obfuscator_internal_symbol_name(value.getName()) && !value.hasLocalLinkage();
}

void enforce_public_obf_symbol_gate(llvm::Module& module) {
  for (llvm::Function& function : module) {
    if (has_public_obfuscator_linkage(function)) {
      report_security_gate_failure("public obfuscator symbol " + function.getName().str());
    }
  }

  for (llvm::GlobalVariable& global : module.globals()) {
    if (has_public_obfuscator_linkage(global)) {
      report_security_gate_failure("public obfuscator symbol " + global.getName().str());
    }
  }

  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (has_public_obfuscator_linkage(alias)) {
      report_security_gate_failure("public obfuscator symbol " + alias.getName().str());
    }
  }
}

}  // namespace

void verify_changed_module(llvm::Module& module) {
  std::string error_text;
  llvm::raw_string_ostream stream(error_text);
  if (llvm::verifyModule(module, &stream)) {
    stream.flush();
    llvm::report_fatal_error(llvm::StringRef(error_text));
  }
}

bool apply_block_split_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                             const obfuscation_config& config,
                             const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) || !state.report.decision.policy.allow_split) {
      continue;
    }

    const block_split_options options = build_block_split_options(config, state.report.decision);
    changed |=
        run_block_split(*state.function, options, state.report.decision.seed).split_count > 0;
  }

  return changed;
}

bool apply_indirect_dispatch_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                   const obfuscation_config& config,
                                   const llvm::StringSet<>* skip_functions) {
  if (!config.indirect_dispatch.enabled) { return false; }

  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_indirect_calls) {
      continue;
    }

    const indirect_dispatch_options options =
        build_indirect_dispatch_options(config, state.report.decision);
    changed |= run_indirect_dispatch(*state.function, options).site_count > 0;
  }

  return changed;
}

bool apply_string_encoding_stage(llvm::Module& module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config,
                                 const virtualized_function_map* virtualized_functions) {
  llvm::StringMap<std::uint64_t> protected_functions = build_function_seed_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  llvm::StringMap<protection_level> protected_levels = build_function_level_map(
      states, [](const function_policy& policy) { return policy.allow_string_encoding; });
  append_virtualized_function_seeds(
      protected_functions, virtualized_functions, [](const function_policy& policy) {
        return policy.allow_string_encoding;
      });
  append_virtualized_function_levels(
      protected_levels, virtualized_functions, [](const function_policy& policy) {
        return policy.allow_string_encoding;
      });

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = run_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }

        return iterator->second;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = protected_levels.find(function_name);
        if (iterator == protected_levels.end()) { return std::nullopt; }

        return iterator->second;
      },
      options,
      config.seed);

  return llvm::any_of(results, [](const string_encoding_result& result) { return result.applied; });
}

bool apply_entropy_initialization_stage(llvm::Module& module, std::uint64_t seed_override) {
  return RunEntropyInitialization(module, seed_override);
}

bool apply_cfg_state_cleanup_stage(llvm::Module& module) { return RunCfgStateCleanup(module); }

bool apply_artifact_cleanup_stage(llvm::Module& module, const obfuscation_config& config) {
  return RunArtifactCleanup(module, build_artifact_cleanup_options(config));
}

bool apply_constant_encoding_stage(llvm::Module& module,
                                   const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                   const obfuscation_config& config,
                                   const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  bool uses_module_planner = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_constant_encoding ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const constant_encoding_options options =
        build_constant_encoding_options(config, state.report.decision);
    if (options.mode == constant_protection_mode::keyed_pool ||
        options.mode == constant_protection_mode::auto_mode ||
        options.mode == constant_protection_mode::all) {
      uses_module_planner = true;
      continue;
    }

    changed |= run_constant_encoding(*state.function, options, state.report.decision.seed)
                   .encoded_count > 0;
  }

  if (uses_module_planner) {
    constant_encoding_options module_options;
    module_options.mode = config.constant_encoding.mode;
    module_options.max_constants_per_function = config.constant_encoding.max_constants_per_function;
    module_options.min_bit_width = config.constant_encoding.min_bit_width;
    module_options.mba_depth = config.mba.depth;
    changed |= run_constant_encoding(
                   module,
                   [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
                     for (const function_pipeline_state& state : states) {
                       if (state.function == nullptr || state.function->isDeclaration() ||
                           should_skip_function(state, skip_functions) ||
                           !state.report.decision.policy.allow_constant_encoding ||
                           state.report.decision.policy.level == protection_level::strong_vm ||
                           state.function->getName() != function_name) {
                         continue;
                       }

                       return state.report.decision.seed;
                     }
                     return std::nullopt;
                   },
                   module_options,
                   config.seed)
                   .encoded_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    changed |= run_instruction_substitution(*state.function, options).substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const obfuscation_config& config,
                            const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_opaque_gep) {
      continue;
    }

    const opaque_gep_options options = build_opaque_gep_options(config, state.report.decision);
    changed |= run_opaque_gep(*state.function, options).lowered_count > 0;
  }

  return changed;
}

bool apply_instruction_substitution_to_functions(
    const virtualized_function_map& virtualized_functions, const obfuscation_config& config) {
  bool changed = false;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_instruction_substitution) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, entry.second.state->report.decision);
    changed |= run_instruction_substitution(*function, options).substitution_count > 0;
  }

  return changed;
}

bool apply_opaque_gep_to_functions(const virtualized_function_map& virtualized_functions,
                                   const obfuscation_config& config) {
  bool changed = false;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

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

bool apply_function_outlining_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                    const obfuscation_config& config,
                                    const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
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

bool apply_function_outlining_to_functions(const virtualized_function_map& virtualized_functions,
                                           const obfuscation_config& config) {
  bool changed = false;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_function_outlining) {
      continue;
    }

    const function_outlining_options options =
        build_function_outlining_options(config, entry.second.state->report.decision);
    changed |= run_function_outlining(*function, options).shard_count > 0;
  }

  return changed;
}

bool apply_opaque_predicate_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                  const obfuscation_config& config,
                                  const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
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

llvm::StringSet<>
apply_control_flattening_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                               const obfuscation_config& config,
                               const llvm::StringSet<>* skip_functions) {
  llvm::StringSet<> flattened_functions;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, state.report.decision);
    const control_flattening_result result = run_control_flattening(*state.function, options);
    if (result.flattened) { flattened_functions.insert(state.function->getName()); }
  }

  return flattened_functions;
}

llvm::StringSet<>
apply_control_flattening_to_functions(const virtualized_function_map& virtualized_functions,
                                      const obfuscation_config& config) {
  llvm::StringSet<> flattened_functions;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_flattening) {
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, entry.second.state->report.decision);
    const control_flattening_result result = run_control_flattening(*function, options);
    if (result.flattened) { flattened_functions.insert(function->getName()); }
  }

  return flattened_functions;
}

bool apply_bogus_control_flow_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                    const obfuscation_config& config,
                                    const llvm::StringSet<>* skip_functions) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, state.report.decision);
    changed |= run_bogus_control_flow(*state.function, options).insertion_count > 0;
  }

  return changed;
}

bool apply_bogus_control_flow_to_functions(const virtualized_function_map& virtualized_functions,
                                           const obfuscation_config& config) {
  bool changed = false;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_bogus_control_flow) {
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, entry.second.state->report.decision);
    changed |= run_bogus_control_flow(*function, options).insertion_count > 0;
  }

  return changed;
}

bool apply_indirect_dispatch_to_functions(const virtualized_function_map& virtualized_functions,
                                          const obfuscation_config& config) {
  if (!config.indirect_dispatch.enabled) { return false; }

  bool changed = false;

  for (const auto& entry : virtualized_functions) {
    llvm::Function* function = entry.second.implementation_function;
    if (function == nullptr || function->isDeclaration()) { continue; }

    if (entry.second.state == nullptr ||
        !entry.second.state->report.decision.policy.allow_indirect_calls) {
      continue;
    }

    const indirect_dispatch_options options =
        build_indirect_dispatch_options(config, entry.second.state->report.decision);
    changed |= run_indirect_dispatch(*function, options).site_count > 0;
  }

  return changed;
}

bool enforce_security_gates(llvm::Module& module,
                            const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const virtualized_function_map& virtualized_functions,
                            const obfuscation_config& config) {
  enforce_strong_vm_virtualization_gate(states, virtualized_functions);
  enforce_strong_vm_string_gate(module, states, virtualized_functions, config);
  enforce_strong_vm_shared_seed_gate(module, states, virtualized_functions);
  enforce_strong_vm_target_cache_gate(module, states, virtualized_functions);
  enforce_strong_vm_implementation_gate(virtualized_functions);

  if (config.security.fail_on_public_obf_symbol) { enforce_public_obf_symbol_gate(module); }

  return false;
}

}  // namespace obf
