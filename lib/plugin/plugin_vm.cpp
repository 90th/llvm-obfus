#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/plugin/internal/plugin_vm_binding_prep.h"
#include "obf/plugin/internal/plugin_vm_callsite_rewriting.h"
#include "obf/plugin/internal/plugin_vm_resolvers.h"
#include "obf/plugin/internal/plugin_vm_target_discovery.h"
#include "obf/plugin/internal/plugin_vm_wrapper_emission.h"
#include "obf/report/coverage_report.h"

#include "obf/vm/virtualize.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Metadata.h"

#include <utility>

namespace obf {

namespace {

void record_vm_function_role(llvm::Function& function,
                             llvm::StringRef owner,
                             llvm::StringRef role,
                             llvm::ArrayRef<llvm::StringRef> obligations) {
  llvm::SmallVector<llvm::StringRef, 8> actual_obligations(obligations.begin(), obligations.end());
  if (read_string_protection_owner(function).has_value()) {
    actual_obligations.push_back("string_owner");
  }
  if (function.hasFnAttribute("vm.string.owner")) {
    actual_obligations.push_back("vm_string_owner");
  }
  record_coverage_role(function, owner, role, actual_obligations);
}

void snapshot_vm_functions(const llvm::Module& module,
                           llvm::SmallPtrSetImpl<const llvm::Function*>& functions) {
  for (const llvm::Function& function : module) { functions.insert(&function); }
}

void record_new_vm_helpers(llvm::Module& module,
                           llvm::StringRef owner,
                           const llvm::SmallPtrSetImpl<const llvm::Function*>& existing_functions,
                           bool lowering_helpers) {
  for (llvm::Function& function : module) {
    if (function.isDeclaration() || existing_functions.contains(&function)) { continue; }
    llvm::SmallVector<llvm::StringRef, 4> obligations;
    if (lowering_helpers) {
      obligations.push_back(function.hasFnAttribute("vm.island.helper") ? "vm_execution"
                                                                     : "vm_lowering_support");
      if (function.hasFnAttribute("vm.island.state")) {
        obligations.push_back("hidden_token_state");
      }
    } else {
      obligations.push_back("vm_entry_resolution");
    }
    record_vm_function_role(function, owner, "generated_vm_helper", obligations);
  }
}

}  // namespace

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
               const obfuscation_config& config,
               const protection_level* only_level) {
  virtualized_function_map virtualized_functions;
  llvm::SmallVector<virtualized_function_binding*, 8> successful_bindings;
  llvm::StringSet<> skip_functions;
  std::uint64_t regional_helper_ordinal = 0;
  llvm::DenseMap<const llvm::Function*, std::size_t> lowering_instruction_counts;

  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr || state.function->isDeclaration() || state.skip_transform_stages ||
        !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (only_level && state.report.decision.policy.level != *only_level) { continue; }

    if (skip_functions.contains(state.function->getName())) { continue; }
    record_string_protection_owner(*state.function, state.report.decision);

    const llvm::SmallVector<vm_target_candidate, 8> target_candidates =
        discover_vm_targets_for_state(state,
                                      skip_functions,
                                      regional_helper_ordinal,
                                      config.debug_preserve_generated_names,
                                      config.vm.max_virtual_instructions);

    for (const vm_target_candidate& target_candidate : target_candidates) {
      llvm::Function* target_function = target_candidate.function;
      if (target_function == nullptr || target_candidate.state == nullptr) { continue; }
      llvm::Module& target_module = *target_function->getParent();
      const bool reporting = coverage_reporting_enabled(target_module);
      const llvm::StringRef owner = read_vm_coverage_owner(*target_candidate.state);
      const llvm::StringRef scope =
          target_candidate.nesting_depth == 0 ? "whole_function" : "regional";

      const function_pipeline_state target_state{.function = target_function,
                                                 .report = target_candidate.state->report,
                                                 .mba_counts = target_candidate.state->mba_counts};
      virtualized_function_binding binding =
          prepare_virtualized_function_binding(target_state, config, scope, owner);
      if (binding.implementation_function == nullptr) { continue; }
      binding.state = target_candidate.state;
      if (reporting) {
        binding.implementation_function->setMetadata(
            "obf.coverage.owner",
            llvm::MDNode::get(target_module.getContext(),
                              {llvm::MDString::get(target_module.getContext(), owner)}));
      }

      vm::virtualization_options vm_options{
          .mba_depth = effective_vm_mba_depth(config),
          .mba_max_ir_instructions = config.mba.max_ir_instructions,
          .mba_enable_polynomial = config.mba.enable_polynomial,
          .mba_enable_multiplication = config.mba.enable_multiplication,
          .max_virtual_instructions = config.vm.max_virtual_instructions,
          .decision_seed = target_candidate.state->report.decision.seed,
          .hidden_token_handshake = true,
          .prefer_island_helpers = true,
          .valid_hidden_tokens = {},
          .symbol_tag = binding.vm_symbol_tag};
      vm_options.valid_hidden_tokens.push_back(binding.wrapper_token);
      for (const virtualized_call_site& site : binding.call_sites) {
        if (site.rewritable) { vm_options.valid_hidden_tokens.push_back(site.hidden_token); }
      }

      // The snapshot stores only identities of existing functions and is bounded
      // by the current module size. Disabled reporting does not populate it.
      llvm::SmallPtrSet<const llvm::Function*, 32> existing_functions;
      if (reporting) { snapshot_vm_functions(target_module, existing_functions); }
      const vm::virtualization_result result =
          vm::run_virtualization(*binding.implementation_function, vm_options);
      if (reporting) {
        record_new_vm_helpers(target_module, owner, existing_functions, /*lowering_helpers=*/true);
      }
      if (!result.virtualized) {
        if (reporting) {
          record_coverage_event(target_module, "emission", "vm", owner, target_function->getName(),
                                "failed", result.detail, result.instruction_count, scope);
        }
        continue;
      }
      if (reporting) {
        lowering_instruction_counts[binding.implementation_function] = result.instruction_count;
      }

      binding.implementation_function->setDSOLocal(true);
      virtualized_function_binding& stored_binding =
          virtualized_functions[target_function->getName()] = std::move(binding);
      successful_bindings.push_back(&stored_binding);
      skip_functions.insert(target_function->getName());
    }
  }

  if (!successful_bindings.empty()) {
    llvm::Module* module = successful_bindings.front()->interface_function == nullptr
                               ? nullptr
                               : successful_bindings.front()->interface_function->getParent();
    if (module != nullptr) {
      llvm::SmallVector<vm_entry_thunk_shape, 8> entry_thunk_shapes;
      entry_thunk_shapes.reserve(successful_bindings.size());
      for (virtualized_function_binding* binding : successful_bindings) {
        if (binding == nullptr || binding->interface_function == nullptr ||
            binding->state == nullptr) {
          entry_thunk_shapes.push_back(vm_entry_thunk_shape::direct_forward);
          continue;
        }

        const llvm::StringRef source_name = binding->interface_function->getName();
        const std::uint64_t seed = binding->state->report.decision.seed;
        entry_thunk_shapes.push_back(select_vm_entry_thunk_shape(source_name, seed));
      }

      rebalance_vm_entry_thunk_shapes(*module, successful_bindings, entry_thunk_shapes);

      for (std::size_t index = 0; index < successful_bindings.size(); ++index) {
        virtualized_function_binding& binding = *successful_bindings[index];
        const bool reporting = coverage_reporting_enabled(*module);
        const llvm::StringRef owner = read_vm_coverage_owner(*binding.state);
        const llvm::StringRef scope =
            binding.interface_function == binding.state->function ? "whole_function" : "regional";
        llvm::Function* entry_thunk_function =
            create_vm_entry_thunk(*binding.interface_function,
                                  *binding.implementation_function,
                                  binding.entry_thunk_function_name,
                                  entry_thunk_shapes[index]);
        if (entry_thunk_function == nullptr) {
          if (reporting) {
            record_coverage_event(*module, "emission", "vm", owner,
                                  binding.interface_function->getName(), "failed",
                                  "VM entry thunk creation failed", 0, scope);
          }
          virtualized_functions.erase(binding.interface_function->getName());
          continue;
        }

        binding.entry_thunk_function = entry_thunk_function;

        const vm_resolver_shape resolver_shape =
            select_vm_resolver_shape(binding.state->report.decision.policy.level,
                                     *binding.interface_function);
        const vm_seed_resolver_shape seed_resolver_shape =
            select_vm_seed_resolver_shape(binding.state->report.decision.policy.level);
        binding.uses_target_cache = resolver_shape == vm_resolver_shape::cached_sentinel_global;
        binding.uses_shared_seed_resolver =
            seed_resolver_shape == vm_seed_resolver_shape::shared_switch_resolver;
        llvm::SmallPtrSet<const llvm::Function*, 32> existing_functions;
        if (reporting) { snapshot_vm_functions(*module, existing_functions); }
        rewrite_vm_interface_wrapper(*binding.interface_function,
                                     *binding.implementation_function,
                                     binding,
                                     binding.wrapper_token,
                                     resolver_shape,
                                     seed_resolver_shape,
                                     effective_vm_mba_depth(config));
        if (reporting) {
          record_new_vm_helpers(*module, owner, existing_functions, /*lowering_helpers=*/false);
          record_vm_function_role(*binding.interface_function, owner,
                                  scope == "regional" ? "regional_wrapper" : "public_wrapper",
                                  {"vm_dispatch", "hidden_token_production"});
          record_vm_function_role(*binding.implementation_function, owner, "vm_implementation",
                                  {"vm_execution", "hidden_token_validation"});
          record_vm_function_role(*binding.entry_thunk_function, owner, "vm_entry_thunk",
                                  {"vm_entry_dispatch", "hidden_token_forwarding"});
          record_coverage_event(*module, "emission", "vm", owner,
                                binding.interface_function->getName(), "emitted",
                                "wrapper rewritten to VM implementation",
                                lowering_instruction_counts.lookup(binding.implementation_function),
                                scope);
        }
      }
    }
  }

  return virtualized_functions;
}

llvm::StringSet<>
collect_virtualized_function_names(const virtualized_function_map& virtualized_functions) {
  llvm::StringSet<> names;
  for (const auto& entry : virtualized_functions) {
    names.insert(entry.getKey());
    if (entry.second.implementation_function != nullptr) {
      names.insert(entry.second.implementation_function->getName());
    }
  }
  return names;
}

void include_vm_parent_functions(llvm::StringSet<>& virtualized_names,
                                 const virtualized_function_map& virtualized_functions) {
  for (const auto& entry : virtualized_functions) {
    const function_pipeline_state* state = entry.second.state;
    if (state == nullptr || state->function == nullptr) { continue; }

    if (entry.getKey() == state->function->getName()) {
      virtualized_names.insert(state->function->getName());
    }
  }
}

llvm::StringSet<>
collect_preserved_site_caller_names(const virtualized_function_map& virtualized_functions) {
  llvm::StringSet<> callers;
  for (const auto& entry : virtualized_functions) {
    for (const virtualized_call_site& site : entry.second.call_sites) {
      if (site.rewritable) { continue; }
      auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(site.call);
      if (call == nullptr) { continue; }
      if (llvm::Function* caller = call->getFunction()) { callers.insert(caller->getName()); }
    }
  }
  return callers;
}

}  // namespace obf
