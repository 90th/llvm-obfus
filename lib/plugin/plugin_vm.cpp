#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/plugin/internal/plugin_vm_binding_prep.h"
#include "obf/plugin/internal/plugin_vm_callsite_rewriting.h"
#include "obf/plugin/internal/plugin_vm_resolvers.h"
#include "obf/plugin/internal/plugin_vm_target_discovery.h"
#include "obf/plugin/internal/plugin_vm_wrapper_emission.h"

#include "obf/vm/virtualize.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/IR/Instructions.h"

#include <utility>

namespace obf {

virtualized_function_map
apply_vm_stage(const llvm::SmallVectorImpl<function_pipeline_state>& states,
               const obfuscation_config& config,
               const protection_level* only_level) {
  virtualized_function_map virtualized_functions;
  llvm::SmallVector<virtualized_function_binding*, 8> successful_bindings;
  llvm::StringSet<> skip_functions;
  std::uint64_t regional_helper_ordinal = 0;

  for (const function_pipeline_state& state : states) {
    if (state.function == nullptr || state.function->isDeclaration() ||
        !state.report.decision.policy.allow_vm) {
      continue;
    }

    if (only_level && state.report.decision.policy.level != *only_level) { continue; }

    if (skip_functions.contains(state.function->getName())) { continue; }

    const llvm::SmallVector<vm_target_candidate, 8> target_candidates =
        discover_vm_targets_for_state(
            state, skip_functions, regional_helper_ordinal, config.debug_preserve_generated_names);

    for (const vm_target_candidate& target_candidate : target_candidates) {
      llvm::Function* target_function = target_candidate.function;
      if (target_function == nullptr || target_candidate.state == nullptr) { continue; }

      const function_pipeline_state target_state{.function = target_function,
                                                 .report = target_candidate.state->report,
                                                 .mba_counts = target_candidate.state->mba_counts};
      virtualized_function_binding binding =
          prepare_virtualized_function_binding(target_state, config);
      if (binding.implementation_function == nullptr) { continue; }
      binding.state = target_candidate.state;

      vm::virtualization_options vm_options{
          .mba_depth = config.mba.depth,
          .mba_max_ir_instructions = config.mba.max_ir_instructions,
          .mba_enable_polynomial = config.mba.enable_polynomial,
          .mba_enable_multiplication = config.mba.enable_multiplication,
          .decision_seed = target_candidate.state->report.decision.seed,
          .hidden_token_handshake = true,
          .prefer_island_helpers = true,
          .valid_hidden_tokens = {},
          .symbol_tag = binding.vm_symbol_tag};
      vm_options.valid_hidden_tokens.push_back(binding.wrapper_token);
      for (const virtualized_call_site& site : binding.call_sites) {
        if (site.rewritable) { vm_options.valid_hidden_tokens.push_back(site.hidden_token); }
      }

      const vm::virtualization_result result =
          vm::run_virtualization(*binding.implementation_function, vm_options);
      if (!result.virtualized) { continue; }

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
        llvm::Function* entry_thunk_function =
            create_vm_entry_thunk(*binding.interface_function,
                                  *binding.implementation_function,
                                  binding.entry_thunk_function_name,
                                  entry_thunk_shapes[index]);
        if (entry_thunk_function == nullptr) {
          virtualized_functions.erase(binding.interface_function->getName());
          continue;
        }

        binding.entry_thunk_function = entry_thunk_function;

        const vm_resolver_shape resolver_shape =
            select_vm_resolver_shape(binding.state->report.decision.policy.level);
        const vm_seed_resolver_shape seed_resolver_shape =
            select_vm_seed_resolver_shape(binding.state->report.decision.policy.level);
        binding.uses_target_cache = resolver_shape == vm_resolver_shape::cached_sentinel_global;
        binding.uses_shared_seed_resolver =
            seed_resolver_shape == vm_seed_resolver_shape::shared_switch_resolver;
        rewrite_vm_interface_wrapper(*binding.interface_function,
                                     *binding.implementation_function,
                                     binding,
                                     binding.wrapper_token,
                                     resolver_shape,
                                     seed_resolver_shape,
                                     config.mba.depth);
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
