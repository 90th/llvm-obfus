#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/plugin/internal/plugin_vm_binding_prep.h"
#include "obf/plugin/internal/plugin_vm_internal.h"
#include "obf/plugin/internal/plugin_vm_resolvers.h"
#include "obf/plugin/internal/plugin_vm_target_discovery.h"
#include "obf/plugin/internal/plugin_vm_wrapper_emission.h"

#include "obf/support/generated_names.h"
#include "obf/transforms/mba.h"
#include "obf/vm/candidate_analysis.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <algorithm>
#include <string>

namespace obf {

namespace {

bool rewrite_calls_to_virtualized_function(const virtualized_function_binding& binding,
                                           std::uint32_t mba_depth) {
  if (binding.interface_function == nullptr || binding.implementation_function == nullptr
      || binding.entry_thunk_function == nullptr) {
    return false;
  }

  llvm::Function& function = *binding.interface_function;
  llvm::Function& thunk_function = *binding.entry_thunk_function;
  llvm::Module* module = function.getParent();
  if (module == nullptr) { return false; }

  const vm_resolver_shape resolver_shape =
      binding.state == nullptr
          ? vm_resolver_shape::cached_sentinel_global
          : select_vm_resolver_shape(binding.state->report.decision.policy.level);
  const vm_seed_resolver_shape seed_resolver_shape =
      binding.state == nullptr
          ? vm_seed_resolver_shape::shared_switch_resolver
          : select_vm_seed_resolver_shape(binding.state->report.decision.policy.level);
  auto* ptr_int_type = get_vm_pointer_int_type(function);
  if (ptr_int_type == nullptr) { return false; }

  llvm::GlobalVariable* target_global = nullptr;
  if (resolver_shape == vm_resolver_shape::cached_sentinel_global) {
    target_global = get_or_create_vm_target_global(function, binding.target_cache_global_name);
    if (target_global == nullptr) { return false; }
  }

  const llvm::APInt key = derive_vm_target_key(function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);
  llvm::GlobalVariable* target_seed_global =
      get_or_create_vm_target_seed_global(function,
                                          thunk_function,
                                          binding.target_seed_global_name,
                                          binding.seed_case_function_name,
                                          ptr_int_type,
                                          seed_resolver_shape,
                                          mba_depth);
  if (target_seed_global == nullptr) { return false; }
  llvm::GlobalVariable* decode_key_global = get_or_create_vm_decode_key_global(
      *module, ptr_int_type, binding.decode_key_global_name, key);

  const std::uint64_t raw_salt = stable_hash_string(function.getName()) * 0x9E3779B97F4A7C15ULL;
  const llvm::APInt salt(ptr_int_type->getBitWidth(),
                         raw_salt == 0 ? 0xC6EF3720ULL : raw_salt,
                         /*isSigned=*/false,
                         /*implicitTrunc=*/true);

  bool changed = false;
  std::size_t callsite_index = 0;
  for (const virtualized_call_site& site : binding.call_sites) {
    llvm::CallBase* call = llvm::dyn_cast_or_null<llvm::CallBase>(site.call);
    if (call == nullptr) { continue; }
    llvm::BasicBlock* call_block = call->getParent();
    if (call_block == nullptr || call->getCalledOperand()->stripPointerCasts() != &function) {
      continue;
    }
    llvm::Function* caller = call_block->getParent();
    if (caller == nullptr) { continue; }

    if (resolver_shape == vm_resolver_shape::local_always_decode) {
      llvm::IRBuilder<> builder(call);
      llvm::Value* hidden_token =
          build_hidden_token_value(builder,
                                   *caller,
                                   (function.getName() + ".obf.call").str(),
                                   site.hidden_token,
                                   mba_depth,
                                   0x700000ULL + static_cast<std::uint64_t>(callsite_index++));
      llvm::Value* encoded_target =
          build_encoded_vm_target_value(builder,
                                        *caller,
                                        function,
                                        thunk_function,
                                        *target_seed_global,
                                        *decode_key_global,
                                        hidden_token,
                                        key,
                                        salt,
                                        (function.getName() + ".obf").str(),
                                        seed_resolver_shape,
                                        site.hidden_token,
                                        0x710000ULL,
                                        mba_depth);
      llvm::Value* decoded_target =
          decode_encoded_vm_target_value(builder,
                                         *caller,
                                         *decode_key_global,
                                         encoded_target,
                                         key,
                                         (function.getName() + ".obf").str(),
                                         site.hidden_token,
                                         0x720000ULL,
                                         mba_depth);
      llvm::Value* indirect_target = builder.CreateIntToPtr(decoded_target,
                                                            call->getCalledOperand()->getType(),
                                                            function.getName() + ".obf.indirect");

      llvm::SmallVector<llvm::Use*, 16> original_uses;
      for (llvm::Use& use : call->uses()) { original_uses.push_back(&use); }

      llvm::SmallVector<llvm::Value*, 8> arguments;
      const std::size_t fixed_arg_count = function.arg_size();
      const std::size_t forwarded_arg_count =
          function.isVarArg() ? std::min<std::size_t>(fixed_arg_count, call->arg_size())
                              : call->arg_size();
      arguments.reserve(forwarded_arg_count + 1);
      std::size_t arg_index = 0;
      for (llvm::Use& argument : call->args()) {
        if (arg_index >= forwarded_arg_count) { break; }
        arguments.push_back(argument.get());
        ++arg_index;
      }
      arguments.push_back(hidden_token);

      auto* rewritten_call = builder.CreateCall(
          thunk_function.getFunctionType(),
          indirect_target,
          arguments,
          call->getType()->isVoidTy() ? "" : function.getName() + ".obf.callsite");
      rewritten_call->setCallingConv(call->getCallingConv());
      rewritten_call->setAttributes(build_vm_safe_callsite_attributes(thunk_function));

      llvm::Type* call_ret_type = rewritten_call->getType();
      if (call_ret_type->isIntegerTy()) {
        llvm::Value* decoded_ret =
            decode_virtualized_integer_return(builder,
                                              *caller,
                                              function.getName(),
                                              make_vm_retkey_global_name(binding.vm_symbol_tag),
                                              rewritten_call,
                                              hidden_token,
                                              site.hidden_token,
                                              mba_depth);

        for (llvm::Use* use : original_uses) { use->set(decoded_ret); }
      } else {
        for (llvm::Use* use : original_uses) { use->set(rewritten_call); }
      }

      call->eraseFromParent();

      changed = true;
      continue;
    }

    llvm::BasicBlock* orig_bb = call->getParent();
    llvm::BasicBlock* call_bb =
        orig_bb->splitBasicBlock(call->getIterator(), (function.getName() + ".obf.call").str());
    orig_bb->getTerminator()->eraseFromParent();

    llvm::BasicBlock* resolve_bb = llvm::BasicBlock::Create(
        module->getContext(), (function.getName() + ".obf.resolve").str(), caller, call_bb);

    llvm::IRBuilder<> entry_builder(orig_bb);
    llvm::Value* hidden_token =
        build_hidden_token_value(entry_builder,
                                 *caller,
                                 (function.getName() + ".obf.call").str(),
                                 site.hidden_token,
                                 mba_depth,
                                 0x700000ULL + static_cast<std::uint64_t>(callsite_index++));
    auto* encoded_check =
        entry_builder.CreateLoad(ptr_int_type, target_global, function.getName() + ".obf.check");
    auto* sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
    auto* is_unresolved = entry_builder.CreateICmpEQ(
        encoded_check, sentinel_const, function.getName() + ".obf.unresolved");
    entry_builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

    llvm::IRBuilder<> resolve_builder(resolve_bb);
    llvm::Value* new_encoded = build_encoded_vm_target_value(resolve_builder,
                                                             *caller,
                                                             function,
                                                             thunk_function,
                                                             *target_seed_global,
                                                             *decode_key_global,
                                                             hidden_token,
                                                             key,
                                                             salt,
                                                             (function.getName() + ".obf").str(),
                                                             seed_resolver_shape,
                                                             site.hidden_token,
                                                             0x710000ULL,
                                                             mba_depth);
    resolve_builder.CreateStore(new_encoded, target_global);
    resolve_builder.CreateBr(call_bb);

    llvm::IRBuilder<> call_builder(call);
    auto* encoded_phi =
        call_builder.CreatePHI(ptr_int_type, 2, function.getName() + ".obf.encoded");
    encoded_phi->addIncoming(encoded_check, orig_bb);
    encoded_phi->addIncoming(new_encoded, resolve_bb);

    llvm::Value* decoded_target =
        decode_encoded_vm_target_value(call_builder,
                                       *caller,
                                       *decode_key_global,
                                       encoded_phi,
                                       key,
                                       (function.getName() + ".obf").str(),
                                       site.hidden_token,
                                       0x720000ULL,
                                       mba_depth);
    llvm::Value* indirect_target = call_builder.CreateIntToPtr(
        decoded_target, call->getCalledOperand()->getType(), function.getName() + ".obf.indirect");

    llvm::SmallVector<llvm::Use*, 16> original_uses;
    for (llvm::Use& use : call->uses()) { original_uses.push_back(&use); }

    llvm::SmallVector<llvm::Value*, 8> arguments;
    const std::size_t fixed_arg_count = function.arg_size();
    const std::size_t forwarded_arg_count =
        function.isVarArg() ? std::min<std::size_t>(fixed_arg_count, call->arg_size())
                            : call->arg_size();
    arguments.reserve(forwarded_arg_count + 1);
    std::size_t arg_index = 0;
    for (llvm::Use& argument : call->args()) {
      if (arg_index >= forwarded_arg_count) { break; }
      arguments.push_back(argument.get());
      ++arg_index;
    }
    arguments.push_back(hidden_token);

    auto* rewritten_call = call_builder.CreateCall(
        thunk_function.getFunctionType(),
        indirect_target,
        arguments,
        call->getType()->isVoidTy() ? "" : function.getName() + ".obf.callsite");
    rewritten_call->setCallingConv(call->getCallingConv());
    rewritten_call->setAttributes(build_vm_safe_callsite_attributes(thunk_function));

    llvm::Type* call_ret_type = rewritten_call->getType();
    if (call_ret_type->isIntegerTy()) {
      llvm::IRBuilder<> decode_builder(call);
      llvm::Value* decoded_ret =
          decode_virtualized_integer_return(decode_builder,
                                            *caller,
                                            function.getName(),
                                            make_vm_retkey_global_name(binding.vm_symbol_tag),
                                            rewritten_call,
                                            hidden_token,
                                            site.hidden_token,
                                            mba_depth);

      for (llvm::Use* use : original_uses) { use->set(decoded_ret); }
    } else {
      for (llvm::Use* use : original_uses) { use->set(rewritten_call); }
    }

    call->eraseFromParent();

    changed = true;
  }

  return changed;
}

}  // namespace

bool rewrite_calls_to_virtualized_functions(llvm::Module&,
                                            const virtualized_function_map& virtualized_functions,
                                            std::uint32_t mba_depth) {
  bool changed = false;
  for (const auto& entry : virtualized_functions) {
    changed |= rewrite_calls_to_virtualized_function(entry.second, mba_depth);
  }

  return changed;
}

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

      vm::virtualization_options vm_options{.mba_depth = config.mba.depth,
                    .mba_max_ir_instructions = config.mba.max_ir_instructions,
                    .mba_enable_polynomial = config.mba.enable_polynomial,
                    .mba_enable_multiplication = config.mba.enable_multiplication,
                    .hidden_token_handshake = true,
                    .prefer_island_helpers = true,
                    .valid_hidden_tokens = {},
                    .symbol_tag = binding.vm_symbol_tag};
      vm_options.valid_hidden_tokens.push_back(binding.wrapper_token);
      for (const virtualized_call_site& site : binding.call_sites) {
        vm_options.valid_hidden_tokens.push_back(site.hidden_token);
      }

      const vm::virtualization_result result =
          vm::run_virtualization(*binding.implementation_function, vm_options);
      if (result.virtualized) {
        binding.implementation_function->setDSOLocal(true);
        virtualized_function_binding& stored_binding =
            virtualized_functions[target_function->getName()] = std::move(binding);
        successful_bindings.push_back(&stored_binding);
        skip_functions.insert(target_function->getName());
      }
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
        if (binding == nullptr || binding->interface_function == nullptr || binding->state == nullptr) {
          entry_thunk_shapes.push_back(vm_entry_thunk_shape::direct_forward);
          continue;
        }

        const llvm::StringRef source_name = binding->interface_function->getName();
        const std::uint64_t seed = binding->state->report.decision.seed;
        const vm_entry_thunk_shape selected_shape = select_vm_entry_thunk_shape(source_name, seed);
        entry_thunk_shapes.push_back(selected_shape);
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

}  // namespace obf
