#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/plugin/internal/plugin_vm_binding_prep.h"
#include "obf/plugin/internal/plugin_vm_internal.h"
#include "obf/plugin/internal/plugin_vm_resolvers.h"
#include "obf/plugin/internal/plugin_vm_target_discovery.h"

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

llvm::StringRef get_vm_entry_thunk_balance_scope_name(const llvm::Module& module);

vm_entry_thunk_shape select_vm_entry_thunk_shape(llvm::StringRef source_name,
                                                 std::uint64_t seed) {
  std::uint64_t state = mix_generated_name_seed(seed, 0xe17e7f00dULL);
  state = mix_generated_name_seed(state, stable_hash_string(source_name));
  return static_cast<vm_entry_thunk_shape>(state % 5U);
}

bool is_weak_vm_entry_thunk_shape(vm_entry_thunk_shape shape) {
  return shape == vm_entry_thunk_shape::direct_forward ||
         shape == vm_entry_thunk_shape::neutral_forward;
}

bool requires_indirect_vm_entry_thunk_emission(vm_entry_thunk_shape shape) {
  return shape == vm_entry_thunk_shape::indirect_ptr_forward ||
         shape == vm_entry_thunk_shape::decoy_guarded_forward;
}

bool can_emit_indirect_vm_entry_thunk(llvm::Function& interface_function) {
  return get_vm_pointer_int_type(interface_function) != nullptr;
}

bool binding_requires_strong_vm_entry_thunk(const virtualized_function_binding& binding) {
  return binding.state != nullptr &&
         binding.state->report.decision.policy.level == protection_level::strong_vm;
}

bool binding_requires_normal_vm_entry_thunk_floor(const virtualized_function_binding& binding,
                                                  std::size_t routed_binding_count) {
  static_cast<void>(routed_binding_count);
  return binding.state != nullptr &&
         binding.state->report.decision.policy.level != protection_level::strong_vm;
}

vm_entry_thunk_shape select_strong_vm_entry_thunk_floor_shape(llvm::StringRef source_name,
                                                              std::uint64_t seed,
                                                              bool allow_indirect_shapes) {
  if (!allow_indirect_shapes) { return vm_entry_thunk_shape::split_forward; }

  std::uint64_t state = mix_generated_name_seed(seed, 0x30f10f5f00dULL);
  state = mix_generated_name_seed(state, stable_hash_string(source_name));

  switch (state % 3U) {
    case 0:
      return vm_entry_thunk_shape::split_forward;
    case 1:
      return vm_entry_thunk_shape::indirect_ptr_forward;
    case 2:
    default:
      return vm_entry_thunk_shape::decoy_guarded_forward;
  }
}

vm_entry_thunk_shape select_normal_vm_entry_thunk_floor_shape(llvm::StringRef source_name,
                                                              std::uint64_t seed,
                                                              std::uint64_t scope_seed,
                                                              std::size_t binding_index,
                                                              bool allow_indirect_shapes) {
  if (!allow_indirect_shapes) { return vm_entry_thunk_shape::split_forward; }

  std::uint64_t state = mix_generated_name_seed(seed, 0x305f00d5f00dULL);
  state = mix_generated_name_seed(state, stable_hash_string(source_name));
  state = mix_generated_name_seed(state, scope_seed ^ 0x57c4f9e21ULL);
  state = mix_generated_name_seed(state, static_cast<std::uint64_t>(binding_index) ^ 0x1b6e5d43ULL);

  switch (state % 3U) {
    case 0:
      return vm_entry_thunk_shape::split_forward;
    case 1:
      return vm_entry_thunk_shape::indirect_ptr_forward;
    case 2:
    default:
      return vm_entry_thunk_shape::decoy_guarded_forward;
  }
}

vm_entry_thunk_shape upgrade_vm_entry_thunk_shape_for_policy(
    llvm::Module& module,
    const virtualized_function_binding& binding,
    std::size_t binding_index,
    std::size_t routed_binding_count,
    vm_entry_thunk_shape shape) {
  if (binding.interface_function == nullptr || binding.state == nullptr) { return shape; }

  llvm::Function& interface_function = *binding.interface_function;
  const protection_level level = binding.state->report.decision.policy.level;
  const std::uint64_t seed = binding.state->report.decision.seed;
  const llvm::StringRef source_name = interface_function.getName();
  const bool allow_indirect_shapes = can_emit_indirect_vm_entry_thunk(interface_function);
  const std::uint64_t scope_seed = stable_hash_string(get_vm_entry_thunk_balance_scope_name(module));

  if (level == protection_level::strong_vm && is_weak_vm_entry_thunk_shape(shape)) {
    return select_strong_vm_entry_thunk_floor_shape(source_name, seed, allow_indirect_shapes);
  }

  if (binding_requires_normal_vm_entry_thunk_floor(binding, routed_binding_count) &&
      is_weak_vm_entry_thunk_shape(shape)) {
    return select_normal_vm_entry_thunk_floor_shape(
        source_name, seed, scope_seed, binding_index, allow_indirect_shapes);
  }

  if (requires_indirect_vm_entry_thunk_emission(shape) && !allow_indirect_shapes) {
    return vm_entry_thunk_shape::split_forward;
  }

  return shape;
}

bool is_high_hardening_vm_entry_thunk_shape(vm_entry_thunk_shape shape) {
  return shape == vm_entry_thunk_shape::indirect_ptr_forward ||
         shape == vm_entry_thunk_shape::decoy_guarded_forward;
}

llvm::StringRef get_vm_entry_thunk_balance_scope_name(const llvm::Module& module) {
  if (!module.getSourceFileName().empty()) { return module.getSourceFileName(); }
  if (!module.getName().empty()) { return module.getName(); }
  return "<anonymous-module>";
}

std::uint64_t compute_vm_entry_thunk_balance_rank(const virtualized_function_binding& binding,
                                                  std::uint64_t scope_seed,
                                                  std::uint64_t salt) {
  llvm::Function* interface_function = binding.interface_function;
  if (interface_function == nullptr) { return mix_generated_name_seed(scope_seed, salt); }

  std::uint64_t rank = mix_generated_name_seed(scope_seed, salt);
  rank = mix_generated_name_seed(rank, stable_hash_string(interface_function->getName()));
  if (binding.state != nullptr) {
    rank = mix_generated_name_seed(rank, binding.state->report.decision.seed);
  }
  return rank;
}

void rebalance_vm_entry_thunk_shapes(llvm::Module& module,
                                     llvm::ArrayRef<virtualized_function_binding*> bindings,
                                     llvm::SmallVectorImpl<vm_entry_thunk_shape>& shapes) {
  if (bindings.size() != shapes.size()) { return; }

  for (std::size_t index = 0; index < bindings.size(); ++index) {
    const virtualized_function_binding* binding = bindings[index];
    if (binding == nullptr) { continue; }

    shapes[index] =
        upgrade_vm_entry_thunk_shape_for_policy(module, *binding, index, bindings.size(), shapes[index]);
  }

  if (bindings.size() < 2) { return; }

  const std::uint64_t scope_seed = stable_hash_string(get_vm_entry_thunk_balance_scope_name(module));

  const auto candidate_priority = [&](std::size_t index) {
    const virtualized_function_binding* binding = bindings[index];
    const bool requires_strong_floor =
        binding != nullptr && binding_requires_strong_vm_entry_thunk(*binding);
    const vm_entry_thunk_shape shape = shapes[index];

    if (!requires_strong_floor && is_weak_vm_entry_thunk_shape(shape)) { return 0; }
    if (!requires_strong_floor && !is_high_hardening_vm_entry_thunk_shape(shape)) { return 1; }
    if (requires_strong_floor && is_weak_vm_entry_thunk_shape(shape)) { return 2; }
    if (requires_strong_floor && !is_high_hardening_vm_entry_thunk_shape(shape)) { return 3; }
    return 4;
  };

  const auto count_shape = [&](vm_entry_thunk_shape shape) {
    return static_cast<std::size_t>(llvm::count(shapes, shape));
  };
  const auto has_shape = [&](vm_entry_thunk_shape shape) { return count_shape(shape) != 0; };
  const auto has_high_hardening = [&]() {
    return llvm::any_of(shapes, [](vm_entry_thunk_shape shape) {
      return is_high_hardening_vm_entry_thunk_shape(shape);
    });
  };
  const auto assign_shape = [&](vm_entry_thunk_shape target_shape,
                                std::uint64_t salt,
                                auto&& eligible) {
    llvm::SmallVector<std::size_t, 8> order;
    order.reserve(bindings.size());
    for (std::size_t index = 0; index < bindings.size(); ++index) { order.push_back(index); }

    std::sort(order.begin(), order.end(), [&](std::size_t lhs, std::size_t rhs) {
      const int lhs_priority = candidate_priority(lhs);
      const int rhs_priority = candidate_priority(rhs);
      if (lhs_priority != rhs_priority) { return lhs_priority < rhs_priority; }

      const std::uint64_t lhs_rank =
          compute_vm_entry_thunk_balance_rank(*bindings[lhs], scope_seed, salt);
      const std::uint64_t rhs_rank =
          compute_vm_entry_thunk_balance_rank(*bindings[rhs], scope_seed, salt);
      if (lhs_rank != rhs_rank) { return lhs_rank < rhs_rank; }

      llvm::Function* lhs_function = bindings[lhs]->interface_function;
      llvm::Function* rhs_function = bindings[rhs]->interface_function;
      const llvm::StringRef lhs_name = lhs_function == nullptr ? llvm::StringRef{}
                                                               : lhs_function->getName();
      const llvm::StringRef rhs_name = rhs_function == nullptr ? llvm::StringRef{}
                                                               : rhs_function->getName();
      return lhs_name < rhs_name;
    });

    for (std::size_t index : order) {
      if (!eligible(shapes[index])) { continue; }
      shapes[index] = target_shape;
      return true;
    }

    return false;
  };

  if (!has_high_hardening()) {
    const bool prefer_decoy = (mix_generated_name_seed(scope_seed, bindings.size()) & 1ULL) != 0;
    const vm_entry_thunk_shape primary_shape = prefer_decoy
                                                   ? vm_entry_thunk_shape::decoy_guarded_forward
                                                   : vm_entry_thunk_shape::indirect_ptr_forward;
    assign_shape(primary_shape, 0x3fb7b4401ULL, [](vm_entry_thunk_shape shape) {
      return !is_high_hardening_vm_entry_thunk_shape(shape);
    });
  }

  if (bindings.size() < 3) { return; }

  if (!has_shape(vm_entry_thunk_shape::indirect_ptr_forward)) {
    const bool assigned = assign_shape(
        vm_entry_thunk_shape::indirect_ptr_forward,
        0x5a2d96e31ULL,
        [](vm_entry_thunk_shape shape) { return !is_high_hardening_vm_entry_thunk_shape(shape); });
    if (!assigned && count_shape(vm_entry_thunk_shape::decoy_guarded_forward) > 1) {
      assign_shape(vm_entry_thunk_shape::indirect_ptr_forward,
                   0x9d1163b51ULL,
                   [](vm_entry_thunk_shape shape) {
                     return shape == vm_entry_thunk_shape::decoy_guarded_forward;
                   });
    }
  }

  if (!has_shape(vm_entry_thunk_shape::decoy_guarded_forward)) {
    const bool assigned = assign_shape(
        vm_entry_thunk_shape::decoy_guarded_forward,
        0x77e6f3ac9ULL,
        [](vm_entry_thunk_shape shape) { return !is_high_hardening_vm_entry_thunk_shape(shape); });
    if (!assigned && count_shape(vm_entry_thunk_shape::indirect_ptr_forward) > 1) {
      assign_shape(vm_entry_thunk_shape::decoy_guarded_forward,
                   0xc215e8c41ULL,
                   [](vm_entry_thunk_shape shape) {
                     return shape == vm_entry_thunk_shape::indirect_ptr_forward;
                   });
    }
  }
}

llvm::StringRef vm_entry_thunk_shape_marker(vm_entry_thunk_shape shape) {
  switch (shape) {
    case vm_entry_thunk_shape::direct_forward:
      return "vm.entry.thunk.shape.direct";
    case vm_entry_thunk_shape::neutral_forward:
      return "vm.entry.thunk.shape.neutral";
    case vm_entry_thunk_shape::split_forward:
      return "vm.entry.thunk.shape.split";
    case vm_entry_thunk_shape::indirect_ptr_forward:
      return "vm.entry.thunk.shape.indirect";
    case vm_entry_thunk_shape::decoy_guarded_forward:
      return "vm.entry.thunk.shape.decoy_indirect";
  }

  llvm_unreachable("unknown vm entry thunk shape");
}

llvm::CallInst* emit_vm_entry_thunk_call(llvm::IRBuilder<>& builder,
                                         llvm::Function& interface_function,
                                         llvm::Function& implementation_function,
                                         llvm::ArrayRef<llvm::Value*> forward_args) {
  const bool returns_void = implementation_function.getReturnType()->isVoidTy();
  auto* inner_call = builder.CreateCall(implementation_function.getFunctionType(),
                                       &implementation_function,
                                       forward_args,
                                       returns_void ? "" : "obf.vm.entry.thunk.call");
  inner_call->setCallingConv(interface_function.getCallingConv());
  inner_call->setAttributes(build_vm_safe_callsite_attributes(implementation_function));
  return inner_call;
}

llvm::CallInst* emit_vm_entry_thunk_indirect_call(llvm::IRBuilder<>& builder,
                                                  llvm::Function& interface_function,
                                                  llvm::Function& implementation_function,
                                                  llvm::StringRef thunk_name,
                                                  llvm::ArrayRef<llvm::Value*> forward_args,
                                                  llvm::StringRef name_prefix,
                                                  std::uint64_t salt) {
  auto* ptr_int_type = get_vm_pointer_int_type(interface_function);
  if (ptr_int_type == nullptr) {
    return emit_vm_entry_thunk_call(
        builder, interface_function, implementation_function, forward_args);
  }

  const std::uint64_t iptr_seed =
      mix_vm_handshake_seed(stable_hash_string(thunk_name), salt);
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) {
    return emit_vm_entry_thunk_call(
        builder, interface_function, implementation_function, forward_args);
  }
  const mba::builder_context iptr_context{
      .entropy_anchor = mba::get_or_create_entropy_anchor(*module),
      .seed_base = iptr_seed,
      .depth = 2,
  };

  const std::string raw_name = (name_prefix + ".raw").str();
  const std::string opaque_name = name_prefix.str();
  const std::string ptr_name = (name_prefix + ".ptr").str();
  const std::string call_name = (name_prefix + ".call").str();
  auto* impl_raw = builder.CreatePtrToInt(&implementation_function, ptr_int_type, raw_name);
  auto* impl_opaque = mba::entangle_value(
      builder, impl_raw, iptr_context, iptr_seed ^ 0x3e9c710fULL, opaque_name);
  auto* impl_ptr = builder.CreateIntToPtr(
      impl_opaque, implementation_function.getType(), ptr_name);
  const bool returns_void = implementation_function.getReturnType()->isVoidTy();
  auto* indirect_call = builder.CreateCall(implementation_function.getFunctionType(),
                                           impl_ptr,
                                           forward_args,
                                           returns_void ? "" : call_name);
  indirect_call->setCallingConv(interface_function.getCallingConv());
  indirect_call->setAttributes(build_vm_safe_callsite_attributes(implementation_function));
  return indirect_call;
}

void emit_vm_entry_thunk_call_and_return(llvm::IRBuilder<>& builder,
                                         llvm::Function& interface_function,
                                         llvm::Function& implementation_function,
                                         llvm::ArrayRef<llvm::Value*> forward_args) {
  llvm::CallInst* inner_call =
      emit_vm_entry_thunk_call(builder, interface_function, implementation_function, forward_args);
  if (implementation_function.getReturnType()->isVoidTy()) {
    builder.CreateRetVoid();
    return;
  }

  builder.CreateRet(inner_call);
}

llvm::Function* create_vm_entry_thunk(llvm::Function& interface_function,
                                      llvm::Function& implementation_function,
                                      llvm::StringRef thunk_name,
                                      vm_entry_thunk_shape shape) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { return nullptr; }

  // thunk has the same function type as the implementation
  auto* thunk = llvm::Function::Create(
      implementation_function.getFunctionType(),
      llvm::GlobalValue::InternalLinkage,
      thunk_name,
      module);
  thunk->setCallingConv(interface_function.getCallingConv());
  thunk->setDSOLocal(true);
  // abi-safe attributes from the interface function, not implementation
  thunk->setAttributes(build_vm_abi_attribute_list(interface_function));
  thunk->addFnAttr(llvm::Attribute::NoInline);
  // string attribute survives artifact cleanup (fn attrs are not stripped, only local value names are)
  thunk->addFnAttr("obf.vm.entry.thunk");
  thunk->addFnAttr(vm_entry_thunk_shape_marker(shape));

  // copy arg names from the implementation
  auto impl_arg = implementation_function.arg_begin();
  for (llvm::Argument& thunk_arg : thunk->args()) {
    thunk_arg.setName(impl_arg->getName());
    ++impl_arg;
  }

  llvm::BasicBlock* entry =
      llvm::BasicBlock::Create(module->getContext(), "obf.vm.entry.thunk", thunk);
  llvm::IRBuilder<> builder(entry);

  llvm::SmallVector<llvm::Value*, 8> forward_args;
  forward_args.reserve(thunk->arg_size());
  for (llvm::Argument& thunk_arg : thunk->args()) { forward_args.push_back(&thunk_arg); }

  if (shape == vm_entry_thunk_shape::neutral_forward && !forward_args.empty() &&
      forward_args.back()->getType()->isIntegerTy(64)) {
    auto* token_type = llvm::cast<llvm::IntegerType>(forward_args.back()->getType());
    forward_args.back() = builder.CreateXor(forward_args.back(),
                                            llvm::ConstantInt::get(token_type, 0),
                                            "obf.vm.entry.thunk.neutral");
  }

  if (shape == vm_entry_thunk_shape::indirect_ptr_forward) {
    // materialize the impl address through an entropy-entangled expression so the call target
    // is not a direct named reference — ghidra must trace the mba chain to identify the impl
    llvm::CallInst* indirect_call = emit_vm_entry_thunk_indirect_call(builder,
                                                                      interface_function,
                                                                      implementation_function,
                                                                      thunk_name,
                                                                      forward_args,
                                                                      "obf.vm.entry.thunk.iptr",
                                                                      0x7a1be84d20cULL);
    if (implementation_function.getReturnType()->isVoidTy()) {
      builder.CreateRetVoid();
    } else {
      builder.CreateRet(indirect_call);
    }
    return thunk;
  }

  if (shape == vm_entry_thunk_shape::decoy_guarded_forward) {
    // add an opaque-false branch to a cold trap block — the decoy never executes
    // but forces ghidra to consider an alternate callgraph edge to the trap
    const std::uint64_t decoy_seed =
        mix_vm_handshake_seed(stable_hash_string(thunk_name), 0xd3c0a77f41bULL);
    llvm::BasicBlock* decoy = llvm::BasicBlock::Create(
        module->getContext(), "obf.vm.entry.thunk.decoy", thunk);
    llvm::BasicBlock* decoy_route = llvm::BasicBlock::Create(
        module->getContext(), "obf.vm.entry.thunk.route", thunk);
    llvm::BasicBlock* decoy_call = llvm::BasicBlock::Create(
        module->getContext(), "obf.vm.entry.thunk.call", thunk);
    llvm::BasicBlock* decoy_ret = llvm::BasicBlock::Create(
        module->getContext(), "obf.vm.entry.thunk.ret", thunk);
    auto* opaque_true = mba::build_entropy_true_predicate(
        builder,
        *thunk,
        /*mba_depth=*/2,
        decoy_seed,
        decoy_seed ^ 0x11ULL,
        decoy_seed ^ 0x22ULL,
        "obf.vm.thunk.decoy.ctx.a",
        "obf.vm.thunk.decoy.ctx.b",
        "obf.vm.thunk.decoy.true");
    auto* opaque_false = builder.CreateNot(opaque_true, "obf.vm.entry.thunk.decoy.cond");
    builder.CreateCondBr(opaque_false, decoy, decoy_route);
    llvm::IRBuilder<> decoy_builder(decoy);
    decoy_builder.CreateCall(
        llvm::Intrinsic::getOrInsertDeclaration(module, llvm::Intrinsic::trap));
    decoy_builder.CreateUnreachable();
    llvm::IRBuilder<> decoy_route_builder(decoy_route);
    decoy_route_builder.CreateBr(decoy_call);
    llvm::IRBuilder<> decoy_call_builder(decoy_call);
    llvm::CallInst* decoy_inner = emit_vm_entry_thunk_indirect_call(decoy_call_builder,
                                                                    interface_function,
                                                                    implementation_function,
                                                                    thunk_name,
                                                                    forward_args,
                                                                    "obf.vm.entry.thunk.decoy.iptr",
                                                                    decoy_seed ^ 0x58ULL);
    decoy_call_builder.CreateBr(decoy_ret);
    llvm::IRBuilder<> decoy_ret_builder(decoy_ret);
    if (implementation_function.getReturnType()->isVoidTy()) {
      decoy_ret_builder.CreateRetVoid();
    } else {
      decoy_ret_builder.CreateRet(decoy_inner);
    }
    return thunk;
  }

  if (shape != vm_entry_thunk_shape::split_forward) {
    emit_vm_entry_thunk_call_and_return(builder,
                                        interface_function,
                                        implementation_function,
                                        forward_args);
    return thunk;
  }

  llvm::BasicBlock* route = llvm::BasicBlock::Create(
      module->getContext(), "obf.vm.entry.thunk.route", thunk);
  llvm::BasicBlock* call_block = llvm::BasicBlock::Create(
      module->getContext(), "obf.vm.entry.thunk.call", thunk);
  llvm::BasicBlock* ret_block = llvm::BasicBlock::Create(
      module->getContext(), "obf.vm.entry.thunk.ret", thunk);

  builder.CreateBr(route);

  llvm::IRBuilder<> route_builder(route);
  route_builder.CreateBr(call_block);

  llvm::IRBuilder<> call_builder(call_block);
  llvm::CallInst* inner_call = emit_vm_entry_thunk_call(
      call_builder, interface_function, implementation_function, forward_args);
  call_builder.CreateBr(ret_block);

  llvm::IRBuilder<> ret_builder(ret_block);
  if (implementation_function.getReturnType()->isVoidTy()) {
    ret_builder.CreateRetVoid();
  } else {
    ret_builder.CreateRet(inner_call);
  }

  return thunk;
}

void rewrite_vm_interface_wrapper(llvm::Function& interface_function,
                                  llvm::Function& implementation_function,
                                  const virtualized_function_binding& binding,
                                  std::uint64_t wrapper_token,
                                  vm_resolver_shape resolver_shape,
                                  vm_seed_resolver_shape seed_resolver_shape,
                                  std::uint32_t mba_depth) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { llvm_unreachable("vm wrapper missing parent module"); }

  // wrapper resolves/calls the entry thunk, not the implementation directly
  llvm::Function& thunk_function = *binding.entry_thunk_function;

  auto* ptr_int_type = get_vm_pointer_int_type(interface_function);
  if (ptr_int_type == nullptr) { llvm_unreachable("vm wrapper missing pointer integer type"); }

  llvm::GlobalVariable* target_global = nullptr;
  if (resolver_shape == vm_resolver_shape::cached_sentinel_global) {
    target_global =
        get_or_create_vm_target_global(interface_function, binding.target_cache_global_name);
    if (target_global == nullptr) { llvm_unreachable("vm target cache global creation failed"); }
  }

  const llvm::APInt key = derive_vm_target_key(interface_function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);
  llvm::GlobalVariable* target_seed_global =
      get_or_create_vm_target_seed_global(interface_function,
                                          thunk_function,
                                          binding.target_seed_global_name,
                                          binding.seed_case_function_name,
                                          ptr_int_type,
                                          seed_resolver_shape,
                                          mba_depth);
  if (target_seed_global == nullptr) { llvm_unreachable("vm target seed global creation failed"); }

  llvm::GlobalVariable* decode_key_global = get_or_create_vm_decode_key_global(
      *module, ptr_int_type, binding.decode_key_global_name, key);

  const std::uint64_t raw_salt =
      stable_hash_string(interface_function.getName()) * 0x9E3779B97F4A7C15ULL;
  const llvm::APInt salt(ptr_int_type->getBitWidth(),
                         raw_salt == 0 ? 0xC6EF3720ULL : raw_salt,
                         /*isSigned=*/false,
                         /*implicitTrunc=*/true);

  interface_function.deleteBody();
  sanitize_vm_wrapper_attributes(interface_function);

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(
      interface_function.getContext(), "entry.obf.vm.wrapper", &interface_function);
  llvm::IRBuilder<> builder(entry);
  const std::string wrapper_prefix = (interface_function.getName() + ".obf.wrapper").str();
  llvm::Value* hidden_token = build_hidden_token_value(
      builder, interface_function, wrapper_prefix, wrapper_token, mba_depth, 0x6000ULL);

  if (resolver_shape == vm_resolver_shape::local_always_decode) {
    llvm::Value* encoded_target = build_encoded_vm_target_value(builder,
                                                                interface_function,
                                                                interface_function,
                                                                thunk_function,
                                                                *target_seed_global,
                                                                *decode_key_global,
                                                                hidden_token,
                                                                key,
                                                                salt,
                                                                wrapper_prefix,
                                                                seed_resolver_shape,
                                                                wrapper_token,
                                                                0x610000ULL,
                                                                mba_depth);
    llvm::Value* decoded_target = decode_encoded_vm_target_value(builder,
                                                                 interface_function,
                                                                 *decode_key_global,
                                                                 encoded_target,
                                                                 key,
                                                                 wrapper_prefix,
                                                                 wrapper_token,
                                                                 0x620000ULL,
                                                                 mba_depth);
    llvm::Value* indirect_target = builder.CreateIntToPtr(
        decoded_target, thunk_function.getType(), wrapper_prefix + ".indirect");

    llvm::SmallVector<llvm::Value*, 8> arguments;
    arguments.reserve(interface_function.arg_size() + 1);
    for (llvm::Argument& argument : interface_function.args()) { arguments.push_back(&argument); }
    arguments.push_back(hidden_token);

    auto* call = builder.CreateCall(
        thunk_function.getFunctionType(),
        indirect_target,
        arguments,
        interface_function.getReturnType()->isVoidTy() ? "" : wrapper_prefix + ".call");
    call->setCallingConv(interface_function.getCallingConv());
    call->setAttributes(build_vm_safe_callsite_attributes(thunk_function));
    if (interface_function.getReturnType()->isVoidTy()) {
      builder.CreateRetVoid();
    } else {
      llvm::Value* wrapper_ret = call;
      if (interface_function.getReturnType()->isIntegerTy()) {
        wrapper_ret =
            decode_virtualized_integer_return(builder,
                                              interface_function,
                                              interface_function.getName(),
                                              make_vm_retkey_global_name(binding.vm_symbol_tag),
                                              call,
                                              hidden_token,
                                              wrapper_token,
                                              mba_depth);
      }
      builder.CreateRet(wrapper_ret);
    }
    return;
  }

  llvm::BasicBlock* resolve_bb =
      llvm::BasicBlock::Create(interface_function.getContext(),
                               (interface_function.getName() + ".obf.wrapper.resolve").str(),
                               &interface_function);
  llvm::BasicBlock* call_bb =
      llvm::BasicBlock::Create(interface_function.getContext(),
                               (interface_function.getName() + ".obf.wrapper.call").str(),
                               &interface_function);

  auto* encoded_check = builder.CreateLoad(ptr_int_type, target_global, wrapper_prefix + ".check");
  auto* sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
  auto* is_unresolved =
      builder.CreateICmpEQ(encoded_check, sentinel_const, wrapper_prefix + ".unresolved");
  builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

  llvm::IRBuilder<> resolve_builder(resolve_bb);
  llvm::Value* new_encoded = build_encoded_vm_target_value(resolve_builder,
                                                           interface_function,
                                                           interface_function,
                                                           thunk_function,
                                                           *target_seed_global,
                                                           *decode_key_global,
                                                           hidden_token,
                                                           key,
                                                           salt,
                                                           wrapper_prefix,
                                                           seed_resolver_shape,
                                                           wrapper_token,
                                                           0x610000ULL,
                                                           mba_depth);
  resolve_builder.CreateStore(new_encoded, target_global);
  resolve_builder.CreateBr(call_bb);

  llvm::IRBuilder<> call_builder(call_bb);
  auto* encoded_phi = call_builder.CreatePHI(ptr_int_type, 2, wrapper_prefix + ".encoded");
  encoded_phi->addIncoming(encoded_check, entry);
  encoded_phi->addIncoming(new_encoded, resolve_bb);

  llvm::Value* decoded_target = decode_encoded_vm_target_value(call_builder,
                                                               interface_function,
                                                               *decode_key_global,
                                                               encoded_phi,
                                                               key,
                                                               wrapper_prefix,
                                                               wrapper_token,
                                                               0x620000ULL,
                                                               mba_depth);
  llvm::Value* indirect_target = call_builder.CreateIntToPtr(
      decoded_target, thunk_function.getType(), wrapper_prefix + ".indirect");

  llvm::SmallVector<llvm::Value*, 8> arguments;
  arguments.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument& argument : interface_function.args()) { arguments.push_back(&argument); }
  arguments.push_back(hidden_token);

  auto* call = call_builder.CreateCall(
      thunk_function.getFunctionType(),
      indirect_target,
      arguments,
      interface_function.getReturnType()->isVoidTy() ? "" : wrapper_prefix + ".call");
  call->setCallingConv(interface_function.getCallingConv());
  call->setAttributes(build_vm_safe_callsite_attributes(thunk_function));
  if (interface_function.getReturnType()->isVoidTy()) {
    call_builder.CreateRetVoid();
  } else {
    llvm::Value* wrapper_ret = call;
    if (interface_function.getReturnType()->isIntegerTy()) {
      wrapper_ret =
          decode_virtualized_integer_return(call_builder,
                                            interface_function,
                                            interface_function.getName(),
                                            make_vm_retkey_global_name(binding.vm_symbol_tag),
                                            call,
                                            hidden_token,
                                            wrapper_token,
                                            mba_depth);
    }
    call_builder.CreateRet(wrapper_ret);
  }
}

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
