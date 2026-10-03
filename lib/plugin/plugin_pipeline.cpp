#include "obf/plugin/obfuscator_plugin_internal.h"
#include "obf/report/coverage_report.h"

#include "obf/transforms/entropy_initialization.h"
#include "obf/vm/candidate_analysis.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ModRef.h"
#include "llvm/Support/raw_ostream.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace obf {

namespace {

bool should_skip_function(const function_pipeline_state& state,
                          const llvm::StringSet<>* skip_functions) {
  if (state.function == nullptr || state.function->isDeclaration() || state.skip_transform_stages) {
    return true;
  }

  return skip_functions != nullptr && skip_functions->contains(state.function->getName());
}

llvm::StringRef coverage_owner(const llvm::Function& function,
                               const function_pipeline_state& state) {
  if (const llvm::MDNode* metadata = function.getMetadata("obf.coverage.owner");
      metadata != nullptr && metadata->getNumOperands() != 0) {
    if (const auto* owner = llvm::dyn_cast<llvm::MDString>(metadata->getOperand(0))) {
      return owner->getString();
    }
  }
  return state.report.features.name;
}

void record_function_emission(llvm::Function& function,
                              const function_pipeline_state& state,
                              llvm::StringRef mechanism,
                              bool emitted,
                              std::size_t count,
                              llvm::StringRef reason) {
  llvm::Module& module = *function.getParent();
  if (!coverage_reporting_enabled(module)) { return; }
  record_coverage_event(module,
                        "emission",
                        mechanism,
                        coverage_owner(function, state),
                        function.getName(),
                        emitted ? "emitted" : "not_emitted",
                        reason,
                        count);
}

void record_stage_skip(const function_pipeline_state& state,
                       llvm::StringRef mechanism,
                       bool policy_allowed,
                       const llvm::StringSet<>* skip_functions,
                       llvm::StringRef exclusion = {}) {
  if (state.function == nullptr ||
      !coverage_reporting_enabled(*state.function->getParent())) {
    return;
  }
  llvm::StringRef reason;
  if (state.function->isDeclaration()) {
    reason = "declaration";
  } else if (state.skip_transform_stages) {
    reason = "transform stages skipped";
  } else if (skip_functions != nullptr &&
             skip_functions->contains(state.function->getName())) {
    reason = "function in stage skip set";
  } else if (!policy_allowed) {
    reason = "effective policy disallows mechanism";
  } else {
    reason = exclusion;
  }
  record_function_emission(*state.function, state, mechanism, false, 0, reason);
}

function_outlining_result run_reported_function_outlining(
    llvm::Function& function,
    const function_outlining_options& options,
    const function_pipeline_state& state) {
  llvm::Module& module = *function.getParent();
  const bool reporting = coverage_reporting_enabled(module);
  llvm::SmallPtrSet<const llvm::Function*, 32> functions_before;
  if (reporting) {
    for (const llvm::Function& existing : module) { functions_before.insert(&existing); }
  }

  function_outlining_result result = run_function_outlining(function, options);
  record_function_emission(
      function, state, "function_outlining", result.shard_count != 0, result.shard_count, result.detail);
  if (!reporting || result.shard_count == 0) { return result; }

  const llvm::StringRef owner = coverage_owner(function, state);
  for (llvm::Function& shard : module) {
    if (shard.isDeclaration() || functions_before.contains(&shard)) { continue; }
    llvm::SmallVector<std::string, 3> preserved;
    for (llvm::StringRef name :
         {"obf.string.owner.seed", "obf.string.owner.level", "vm.string.owner"}) {
      if (!shard.hasFnAttribute(name)) { continue; }
      const llvm::StringRef value = shard.getFnAttribute(name).getValueAsString();
      std::string obligation;
      obligation.reserve(name.size() + (value.empty() ? 0 : value.size() + 1));
      obligation.append(name.data(), name.size());
      if (!value.empty()) {
        obligation += '=';
        obligation.append(value.data(), value.size());
      }
      preserved.push_back(std::move(obligation));
    }
    llvm::SmallVector<llvm::StringRef, 3> obligations;
    for (const std::string& obligation : preserved) { obligations.push_back(obligation); }
    shard.setMetadata("obf.coverage.owner",
                       llvm::MDNode::get(module.getContext(),
                                         llvm::MDString::get(module.getContext(), owner)));
    record_coverage_role(shard, owner, "outlined_shard", obligations);
  }
  return result;
}

void record_security_gate_rejection(llvm::Module& module, llvm::StringRef reason) {
  if (!coverage_reporting_enabled(module)) { return; }
  record_coverage_event(module,
                        "finalization",
                        "security_gates",
                        "",
                        module.getName(),
                        "rejected",
                        reason,
                        0,
                        "module");
  write_coverage_report(module);
}

[[noreturn]] void report_security_gate_failure(llvm::Module& module, llvm::StringRef detail) {
  std::string message = "security gate failure: ";
  message += detail.str();
  record_security_gate_rejection(module, message);
  llvm::report_fatal_error(llvm::StringRef(message));
}

[[noreturn]] void report_strong_vm_invariant_violation(llvm::Module& module,
                                                     llvm::StringRef detail) {
  std::string message = "strong_vm invariant violation: ";
  message += detail.str();
  record_security_gate_rejection(module, message);
  llvm::report_fatal_error(llvm::StringRef(message));
}

bool is_strong_vm_state(const function_pipeline_state& state) {
  return state.function != nullptr && !state.function->isDeclaration() &&
         state.report.decision.policy.level == protection_level::strong_vm;
}

bool binding_belongs_to_state(const virtualized_function_binding& binding,
                              const function_pipeline_state& state) {
  if (binding.state == &state || binding.interface_function == state.function) { return true; }

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
  if (reason.contains("too many virtual instructions")) {
    return "virtual_instruction_budget_exceeded";
  }
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
  if (reason_tag == "virtual_instruction_budget_exceeded") {
    return "reduce function size, lower mba.depth or set vm.max_mba_depth, raise "
           "vm.max_virtual_instructions, or compile the source with -O1 -fno-inline";
  }
  return "review candidate analysis detail and adjust function policy";
}

void enforce_strong_vm_virtualization_gate(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const virtualized_function_map& virtualized_functions,
    const obfuscation_config& config) {
  for (const function_pipeline_state& state : states) {
    if (!is_strong_vm_state(state) || !state.report.decision.policy.allow_vm ||
        has_virtualized_binding_for_state(virtualized_functions, state)) {
      continue;
    }

    const vm::candidate_result result =
        vm::analyze_candidate(*state.function, nullptr, config.vm.max_virtual_instructions);
    std::string detail = "function ";
    detail += state.function->getName().str();
    detail += " was not virtualized; policy_source=";
    detail += std::string(to_string(state.report.decision.source));
    detail += "; policy_detail=";
    detail += state.report.decision.detail;
    detail += "; reason=";
    const llvm::StringRef reason = result.detail.empty()
                                       ? llvm::StringRef("no whole-function or regional VM target")
                                       : llvm::StringRef(result.detail);
    detail += reason.str();
    const llvm::StringRef reason_tag = classify_vm_candidate_reason_tag(reason);
    detail += "; reason_tag=";
    detail += reason_tag.str();
    detail += "; remediation=";
    detail += vm_candidate_reason_remediation(reason_tag).str();
    report_strong_vm_invariant_violation(*state.function->getParent(), detail);
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
  const llvm::StringMap<string_protection_owner> protected_functions =
      build_string_protection_map(module, states, &virtualized_functions);

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = analyze_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }
        return iterator->second.seed;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }
        return iterator->second.level;
      },
      options,
      config.seed);

  for (const string_encoding_result& result : results) {
    // Producer-tagged binary/local outcomes are excluded by discovery. A
    // prospective strategy cannot excuse a surviving protected source here.
    if (!result.has_strong_vm_use) { continue; }

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
    report_strong_vm_invariant_violation(module, detail);
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
  if (!attribute.hasKindAsEnum()) { return false; }
  switch (attribute.getKindAsEnum()) {
    case llvm::Attribute::Memory:
      // Explicit all-memory readwrite is the conservative unknown effect,
      // equivalent to an absent memory attribute. Reject restrictions on
      // access kind or location, not this redundant spelling of unknown.
      return attribute.getMemoryEffects() != llvm::MemoryEffects::unknown();
    case llvm::Attribute::MustProgress:
    case llvm::Attribute::NoFree:
    case llvm::Attribute::NoRecurse:
    case llvm::Attribute::NoSync:
    case llvm::Attribute::WillReturn:
    case llvm::Attribute::ReadNone:
    case llvm::Attribute::ReadOnly:
    case llvm::Attribute::Speculatable:
      return true;
    default:
      return false;
  }
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
    report_strong_vm_invariant_violation(*function->getParent(), detail);
  }
}

void enforce_strong_vm_implementation_gate(llvm::Module& module,
                                           const virtualized_function_map& virtualized_functions) {
  for (const auto& entry : virtualized_functions) {
    const virtualized_function_binding& binding = entry.second;
    if (!is_strong_vm_binding(binding)) { continue; }

    const std::string name = describe_strong_vm_binding_name(entry, binding);
    if (binding.implementation_function == nullptr) {
      report_strong_vm_invariant_violation(module, "function " + name + " has no VM implementation");
    }

    if (!binding.implementation_function->hasLocalLinkage()) {
      report_strong_vm_invariant_violation(module,
                                           "function " + name + " VM implementation has public linkage");
    }

    enforce_strong_vm_function_attributes(binding.interface_function, name, "wrapper");
    enforce_strong_vm_function_attributes(
        binding.implementation_function, name, "VM implementation");
  }
}

bool function_calls_with_prefix(llvm::Function* function, llvm::StringRef callee_prefix) {
  if (function == nullptr || function->isDeclaration()) { return false; }

  for (llvm::BasicBlock& block : *function) {
    for (llvm::Instruction& instruction : block) {
      auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call == nullptr) { continue; }
      const llvm::Function* callee = call->getCalledFunction();
      if (callee != nullptr && callee->getName().starts_with(callee_prefix)) { return true; }
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
      report_strong_vm_invariant_violation(module,
                                           state.function->getName().str() + " used shared seed resolver");
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
        report_strong_vm_invariant_violation(
            module, interface_function->getName().str() + " used shared seed resolver");
      }
    }

    if (!binding.seed_case_function_name.empty() &&
        module.getFunction(binding.seed_case_function_name) != nullptr) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(module, name.str() + " used shared seed resolver");
    }

    if (binding.uses_shared_seed_resolver) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(module, name.str() + " used shared seed resolver");
    }

    if (function_calls_with_prefix(binding.interface_function, "__obf_vm_seed_resolve") ||
        function_calls_with_prefix(binding.implementation_function, "__obf_vm_seed_resolve")) {
      const llvm::StringRef name = interface_function != nullptr ? interface_function->getName()
                                                                 : llvm::StringRef(entry.getKey());
      report_strong_vm_invariant_violation(module, name.str() + " used shared seed resolver");
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
      report_strong_vm_invariant_violation(
          module, state.function->getName().str() + " emitted target-cache resolver");
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
      report_strong_vm_invariant_violation(
          module, binding.interface_function->getName().str() + " emitted target-cache resolver");
    }

    if (binding.uses_target_cache) {
      report_strong_vm_invariant_violation(
          module, binding.interface_function->getName().str() + " emitted target-cache resolver");
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
      report_security_gate_failure(module, "public obfuscator symbol " + function.getName().str());
    }
  }

  for (llvm::GlobalVariable& global : module.globals()) {
    if (has_public_obfuscator_linkage(global)) {
      report_security_gate_failure(module, "public obfuscator symbol " + global.getName().str());
    }
  }

  for (llvm::GlobalAlias& alias : module.aliases()) {
    if (has_public_obfuscator_linkage(alias)) {
      report_security_gate_failure(module, "public obfuscator symbol " + alias.getName().str());
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
      record_stage_skip(state, "block_split", state.report.decision.policy.allow_split, skip_functions);
      continue;
    }

    const block_split_options options = build_block_split_options(config, state.report.decision);
    const block_split_result result =
        run_block_split(*state.function, options, state.report.decision.seed);
    changed |= result.split_count > 0;
    record_function_emission(
        *state.function, state, "block_split", result.split_count > 0, result.split_count, result.detail);
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
      record_stage_skip(
          state, "indirect_dispatch", state.report.decision.policy.allow_indirect_calls, skip_functions);
      continue;
    }

    const indirect_dispatch_options options =
        build_indirect_dispatch_options(config, state.report.decision);
    const indirect_dispatch_result result = run_indirect_dispatch(*state.function, options);
    changed |= result.site_count > 0;
    record_function_emission(
        *state.function, state, "indirect_dispatch", result.site_count > 0, result.site_count, result.detail);
  }

  return changed;
}

bool apply_string_encoding_stage(llvm::Module& module,
                                 const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config,
                                 const virtualized_function_map* virtualized_functions) {
  const llvm::StringMap<string_protection_owner> protected_functions =
      build_string_protection_map(module, states, virtualized_functions);

  const string_encoding_options options = build_string_encoding_options(config);
  const std::vector<string_encoding_result> results = run_string_encoding(
      module,
      [&](llvm::StringRef function_name) -> std::optional<std::uint64_t> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }

        return iterator->second.seed;
      },
      [&](llvm::StringRef function_name) -> std::optional<protection_level> {
        const auto iterator = protected_functions.find(function_name);
        if (iterator == protected_functions.end()) { return std::nullopt; }

        return iterator->second.level;
      },
      options,
      config.seed);

  if (coverage_reporting_enabled(module)) {
    for (const string_encoding_result& result : results) {
      constexpr llvm::StringLiteral fallback_prefix = "; fallback_reason=";
      constexpr llvm::StringLiteral inline_prefix = "; inline_detail=";
      std::string reason;
      reason.reserve(result.detail.size() +
                     (result.fallback_reason.empty()
                          ? 0
                          : fallback_prefix.size() + result.fallback_reason.size()) +
                     (result.inline_detail.empty()
                          ? 0
                          : inline_prefix.size() + result.inline_detail.size()));
      reason += result.detail;
      if (!result.fallback_reason.empty()) {
        reason.append(fallback_prefix.data(), fallback_prefix.size());
        reason += result.fallback_reason;
      }
      if (!result.inline_detail.empty()) {
        reason.append(inline_prefix.data(), inline_prefix.size());
        reason += result.inline_detail;
      }
      // This is the global result aggregate. Exact per-owner/helper associations
      // are recorded at the string emitter, where the selected plan is available.
      record_coverage_event(module,
                            "emission",
                            "string_encoding",
                            "",
                            result.global_name,
                            result.applied ? "emitted" : "not_emitted",
                            reason,
                            result.rewritten_use_count,
                            "global");
    }
  }

  return llvm::any_of(results, [](const string_encoding_result& result) { return result.applied; });
}

bool apply_entropy_initialization_stage(llvm::Module& module, std::uint64_t seed_override) {
  const bool reporting = coverage_reporting_enabled(module);
  llvm::SmallPtrSet<const llvm::Function*, 32> functions_before;
  if (reporting) {
    for (const llvm::Function& function : module) { functions_before.insert(&function); }
  }
  const bool changed = RunEntropyInitialization(module, seed_override);
  if (reporting) {
    record_coverage_event(module,
                          "emission",
                          "entropy_initialization",
                          "",
                          module.getName(),
                          changed ? "emitted" : "not_emitted",
                          changed ? "shared module entropy runtime initialized; no per-function owner"
                                  : "no module entropy initialization changes",
                          0,
                          "module");
    for (llvm::Function& function : module) {
      if (function.isDeclaration() || functions_before.contains(&function)) { continue; }
      const llvm::StringRef obligations[] = {"entropy_initialization"};
      record_coverage_role(function, "", "entropy_runtime", obligations);
    }
  }
  return changed;
}

bool apply_cfg_state_cleanup_stage(llvm::Module& module) {
  const bool changed = RunCfgStateCleanup(module);
  if (changed && coverage_reporting_enabled(module)) {
    record_coverage_event(module,
                          "emission",
                          "cfg_state_cleanup",
                          "",
                          module.getName(),
                          "completed",
                          "module CFG state cleanup changed IR",
                          0,
                          "module");
  }
  return changed;
}

bool apply_artifact_cleanup_stage(llvm::Module& module, const obfuscation_config& config) {
  const bool changed = RunArtifactCleanup(module, build_artifact_cleanup_options(config));
  if (changed && coverage_reporting_enabled(module)) {
    record_coverage_event(module,
                          "emission",
                          "artifact_cleanup",
                          "",
                          module.getName(),
                          "completed",
                          "module artifact cleanup changed IR",
                          0,
                          "module");
  }
  return changed;
}

bool apply_self_checksum_stage(llvm::Module& module,
                               const llvm::SmallVectorImpl<function_pipeline_state>& states,
                               const obfuscation_config& config) {
  if (!config.self_checksum.enabled) { return false; }

  const self_checksum_options options = {
      .enabled = true,
      .sample_window_bytes = config.self_checksum.window_size,
      .max_checksum_sites = config.self_checksum.max_sites,
      .seed = config.self_checksum.seed != 0 ? config.self_checksum.seed : config.seed};

  bool changed = false;
  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, nullptr) || !state.report.decision.policy.allow_self_checksum) {
      record_stage_skip(state, "self_checksum", state.report.decision.policy.allow_self_checksum, nullptr);
      continue;
    }

    const self_checksum_result result = transform_self_checksum(*state.function, module, options);
    changed |= result.checksum_site_count != 0;
    record_function_emission(*state.function,
                              state,
                              "self_checksum",
                              result.checksum_site_count != 0,
                              result.checksum_site_count,
                              result.detail);
  }

  return changed;
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
      record_stage_skip(state,
                         "constant_encoding",
                         state.report.decision.policy.allow_constant_encoding,
                         skip_functions,
                         "strong_vm native-stage exclusion");
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

    const constant_encoding_result result =
        run_constant_encoding(*state.function, options, state.report.decision.seed);
    changed |= result.encoded_count > 0;
    record_function_emission(*state.function,
                              state,
                              "constant_encoding",
                              result.encoded_count > 0,
                              result.encoded_count,
                              result.detail);
  }

  if (uses_module_planner) {
    constant_encoding_options module_options;
    module_options.mode = config.constant_encoding.mode;
    module_options.max_constants_per_function = config.constant_encoding.max_constants_per_function;
    module_options.min_bit_width = config.constant_encoding.min_bit_width;
    module_options.mba_depth = config.mba.depth;
    const constant_encoding_result result = run_constant_encoding(
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
                   config.seed);
    changed |= result.encoded_count > 0;
    if (coverage_reporting_enabled(module)) {
      record_coverage_event(module,
                            "emission",
                            "constant_encoding",
                            "",
                            module.getName(),
                            result.encoded_count > 0 ? "emitted" : "not_emitted",
                            result.detail,
                            result.encoded_count,
                            "module");
    }
  }

  return changed;
}
namespace {

bool apply_instruction_substitution_stage_impl(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const llvm::StringSet<>* skip_functions,
    const instruction_substitution_stage_candidates* candidates_by_function) {
  bool changed = false;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      record_stage_skip(state,
                         "instruction_substitution",
                         state.report.decision.policy.allow_instruction_substitution,
                         skip_functions,
                         "strong_vm native-stage exclusion");
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    if (candidates_by_function == nullptr) {
      const instruction_substitution_result result =
          run_instruction_substitution(*state.function, options);
      changed |= result.substitution_count > 0;
      record_function_emission(*state.function,
                                state,
                                "instruction_substitution",
                                result.substitution_count > 0,
                                result.substitution_count,
                                result.detail);
      continue;
    }

    const auto candidate_it = candidates_by_function->find(state.function);
    if (candidate_it == candidates_by_function->end()) {
      record_function_emission(
          *state.function, state, "instruction_substitution", false, 0, "no snapshotted candidate sites");
      continue;
    }

    const instruction_substitution_result result =
        run_instruction_substitution(*state.function, options, candidate_it->second);
    changed |= result.substitution_count > 0;
    record_function_emission(*state.function,
                              state,
                              "instruction_substitution",
                              result.substitution_count > 0,
                              result.substitution_count,
                              result.detail);
  }

  return changed;
}

}  // namespace

instruction_substitution_stage_candidates snapshot_instruction_substitution_stage_candidates(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const llvm::StringSet<>* skip_functions) {
  instruction_substitution_stage_candidates candidates_by_function;

  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_instruction_substitution ||
        state.report.decision.policy.level == protection_level::strong_vm) {
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, state.report.decision);
    instruction_substitution_sites candidates =
        collect_instruction_substitution_sites(*state.function, options);
    if (candidates.empty()) { continue; }

    candidates_by_function[state.function] = std::move(candidates);
  }

  return candidates_by_function;
}

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const llvm::StringSet<>* skip_functions) {
  return apply_instruction_substitution_stage_impl(states, config, skip_functions, nullptr);
}

bool apply_instruction_substitution_stage(
    const llvm::SmallVectorImpl<function_pipeline_state>& states,
    const obfuscation_config& config,
    const instruction_substitution_stage_candidates& candidates,
    const llvm::StringSet<>* skip_functions) {
  return apply_instruction_substitution_stage_impl(states, config, skip_functions, &candidates);
}

bool apply_zero_comparison_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
                                 const obfuscation_config& config,
                                 const llvm::StringSet<>* skip_functions) {
  if (!config.zero_comparison.enabled) { return false; }

  bool changed = false;
  for (const function_pipeline_state& state : states) {
    if (should_skip_function(state, skip_functions) ||
        !state.report.decision.policy.allow_zero_comparison) {
      record_stage_skip(
          state, "zero_comparison", state.report.decision.policy.allow_zero_comparison, skip_functions);
      continue;
    }

    const zero_comparison_options options =
        build_zero_comparison_options(config, state.report.decision);
    const zero_comparison_result result = run_zero_comparison(*state.function, options);
    changed |= result.transformed_site_count > 0;
    record_function_emission(*state.function,
                              state,
                              "zero_comparison",
                              result.transformed_site_count > 0,
                              result.transformed_site_count,
                              result.detail);
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
      record_stage_skip(
          state, "opaque_gep", state.report.decision.policy.allow_opaque_gep, skip_functions);
      continue;
    }

    const opaque_gep_options options = build_opaque_gep_options(config, state.report.decision);
    const opaque_gep_result result = run_opaque_gep(*state.function, options);
    changed |= result.lowered_count > 0;
    record_function_emission(
        *state.function, state, "opaque_gep", result.lowered_count > 0, result.lowered_count, result.detail);
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "instruction_substitution",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const instruction_substitution_options options =
        build_instruction_substitution_options(config, entry.second.state->report.decision);
    const instruction_substitution_result result = run_instruction_substitution(*function, options);
    changed |= result.substitution_count > 0;
    record_function_emission(*function,
                              *entry.second.state,
                              "instruction_substitution",
                              result.substitution_count > 0,
                              result.substitution_count,
                              result.detail);
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "opaque_gep",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const opaque_gep_options options =
        build_opaque_gep_options(config, entry.second.state->report.decision);
    const opaque_gep_result result = run_opaque_gep(*function, options);
    changed |= result.lowered_count > 0;
    record_function_emission(*function,
                              *entry.second.state,
                              "opaque_gep",
                              result.lowered_count > 0,
                              result.lowered_count,
                              result.detail);
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
      record_stage_skip(state,
                         "function_outlining",
                         state.report.decision.policy.allow_function_outlining,
                         skip_functions);
      continue;
    }

    record_string_protection_owner(*state.function, state.report.decision);
    const function_outlining_options options =
        build_function_outlining_options(config, state.report.decision);
    changed |= run_reported_function_outlining(*state.function, options, state).shard_count > 0;
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "function_outlining",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const function_outlining_options options =
        build_function_outlining_options(config, entry.second.state->report.decision);
    changed |=
        run_reported_function_outlining(*function, options, *entry.second.state).shard_count > 0;
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
      record_stage_skip(state,
                         "opaque_predicates",
                         state.report.decision.policy.allow_opaque_predicates,
                         skip_functions);
      continue;
    }

    const opaque_predicate_options options =
        build_opaque_predicate_options(config, state.report.decision);
    const opaque_predicate_result result = run_opaque_predicates(*state.function, options);
    changed |= result.insertion_count > 0;
    record_function_emission(*state.function,
                              state,
                              "opaque_predicates",
                              result.insertion_count > 0,
                              result.insertion_count,
                              result.detail);
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
      record_stage_skip(
          state, "control_flattening", state.report.decision.policy.allow_flattening, skip_functions);
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, state.report.decision);
    const control_flattening_result result = run_control_flattening(*state.function, options);
    record_function_emission(*state.function,
                              state,
                              "control_flattening",
                              result.flattened,
                              result.state_count,
                              result.detail);
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "control_flattening",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const control_flattening_options options =
        build_control_flattening_options(config, entry.second.state->report.decision);
    const control_flattening_result result = run_control_flattening(*function, options);
    record_function_emission(*function,
                              *entry.second.state,
                              "control_flattening",
                              result.flattened,
                              result.state_count,
                              result.detail);
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
      record_stage_skip(state,
                         "bogus_control_flow",
                         state.report.decision.policy.allow_bogus_control_flow,
                         skip_functions);
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, state.report.decision);
    const bogus_control_flow_result result = run_bogus_control_flow(*state.function, options);
    changed |= result.insertion_count > 0;
    record_function_emission(*state.function,
                              state,
                              "bogus_control_flow",
                              result.insertion_count > 0,
                              result.insertion_count,
                              result.detail);
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "bogus_control_flow",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const bogus_control_flow_options options =
        build_bogus_control_flow_options(config, entry.second.state->report.decision);
    const bogus_control_flow_result result = run_bogus_control_flow(*function, options);
    changed |= result.insertion_count > 0;
    record_function_emission(*function,
                              *entry.second.state,
                              "bogus_control_flow",
                              result.insertion_count > 0,
                              result.insertion_count,
                              result.detail);
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
      if (entry.second.state != nullptr) {
        record_function_emission(*function,
                                  *entry.second.state,
                                  "indirect_dispatch",
                                  false,
                                  0,
                                  "effective policy disallows mechanism");
      }
      continue;
    }

    const indirect_dispatch_options options =
        build_indirect_dispatch_options(config, entry.second.state->report.decision);
    const indirect_dispatch_result result = run_indirect_dispatch(*function, options);
    changed |= result.site_count > 0;
    record_function_emission(*function,
                              *entry.second.state,
                              "indirect_dispatch",
                              result.site_count > 0,
                              result.site_count,
                              result.detail);
  }

  return changed;
}

bool enforce_security_gates(llvm::Module& module,
                            const llvm::SmallVectorImpl<function_pipeline_state>& states,
                            const virtualized_function_map& virtualized_functions,
                            const obfuscation_config& config) {
  enforce_strong_vm_virtualization_gate(states, virtualized_functions, config);
  enforce_strong_vm_string_gate(module, states, virtualized_functions, config);
  enforce_strong_vm_shared_seed_gate(module, states, virtualized_functions);
  enforce_strong_vm_target_cache_gate(module, states, virtualized_functions);
  enforce_strong_vm_implementation_gate(module, virtualized_functions);

  if (config.security.fail_on_public_obf_symbol) { enforce_public_obf_symbol_gate(module); }

  return false;
}

}  // namespace obf
