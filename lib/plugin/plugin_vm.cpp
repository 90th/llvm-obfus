#include "obf/plugin/obfuscator_plugin_internal.h"

#include "obf/transforms/mba.h"
#include "obf/vm/candidate_analysis.h"
#include "obf/vm/virtualize.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <optional>
#include <string>

namespace obf {

namespace {

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

    const auto append_candidate =
        [&](llvm::SmallVectorImpl<llvm::BasicBlock *> &region_blocks) {
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
          llvm::SmallVector<llvm::BasicBlock *, 8> stored_blocks(
              region_blocks.begin(), region_blocks.end());
          candidates.push_back(vm_region_candidate{.header = &block,
                                                   .region_blocks =
                                                       std::move(stored_blocks),
                                                   .score = instruction_count});
        };

    llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks;
    llvm::BasicBlock *true_block = branch->getSuccessor(0);
    llvm::BasicBlock *false_block = branch->getSuccessor(1);
    if (true_block != false_block && llvm::pred_size(true_block) == 1 &&
        llvm::pred_size(false_block) == 1) {
      auto *true_term = llvm::dyn_cast<llvm::BranchInst>(true_block->getTerminator());
      auto *false_term =
          llvm::dyn_cast<llvm::BranchInst>(false_block->getTerminator());
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
      if (successor == nullptr || successor == &block ||
          llvm::pred_size(successor) != 1) {
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
    region_blocks.push_back(
        llvm::cast<llvm::BasicBlock>(value_map.lookup(region_block)));
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
  llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks(
      candidate.region_blocks.begin(), candidate.region_blocks.end());
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
    targets.push_back(
        {.function = state.function, .state = &state, .nesting_depth = 0});
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

bool is_vm_abi_safe_return_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) {
    return false;
  }

  switch (attribute.getKindAsEnum()) {
  case llvm::Attribute::InReg:
  case llvm::Attribute::SExt:
  case llvm::Attribute::ZExt:
    return true;
  default:
    return false;
  }
}

bool is_vm_abi_safe_parameter_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) {
    return false;
  }

  switch (attribute.getKindAsEnum()) {
  case llvm::Attribute::Alignment:
  case llvm::Attribute::ByRef:
  case llvm::Attribute::ByVal:
  case llvm::Attribute::ElementType:
  case llvm::Attribute::InAlloca:
  case llvm::Attribute::InReg:
  case llvm::Attribute::Nest:
  case llvm::Attribute::Preallocated:
  case llvm::Attribute::SExt:
  case llvm::Attribute::StructRet:
  case llvm::Attribute::SwiftAsync:
  case llvm::Attribute::SwiftError:
  case llvm::Attribute::SwiftSelf:
  case llvm::Attribute::ZExt:
    return true;
  default:
    return false;
  }
}

llvm::AttributeList build_vm_abi_attribute_list(const llvm::Function &function) {
  llvm::LLVMContext &context = function.getContext();
  const llvm::AttributeList original = function.getAttributes();
  llvm::AttributeList sanitized;

  for (llvm::Attribute attribute : original.getRetAttrs()) {
    if (is_vm_abi_safe_return_attribute(attribute)) {
      sanitized = sanitized.addRetAttribute(context, attribute);
    }
  }

  for (const llvm::Argument &argument : function.args()) {
    const unsigned argument_index = argument.getArgNo();
    for (llvm::Attribute attribute : original.getParamAttrs(argument_index)) {
      if (is_vm_abi_safe_parameter_attribute(attribute)) {
        sanitized = sanitized.addAttributeAtIndex(
            context, llvm::AttributeList::FirstArgIndex + argument_index,
            attribute);
      }
    }
  }

  return sanitized;
}

llvm::AttributeList build_vm_safe_callsite_attributes(
    const llvm::Function &callee_function) {
  return build_vm_abi_attribute_list(callee_function);
}

void sanitize_vm_implementation_attributes(
    llvm::Function &implementation_function,
    const llvm::Function &interface_function) {
  implementation_function.setAttributes(
      build_vm_abi_attribute_list(interface_function));
  implementation_function.setDSOLocal(true);
  implementation_function.addFnAttr(llvm::Attribute::NoInline);
}

void sanitize_vm_wrapper_attributes(llvm::Function &interface_function) {
  interface_function.setAttributes(build_vm_abi_attribute_list(interface_function));
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
      implementation_type, llvm::GlobalValue::InternalLinkage,
      ("__obf_vm_impl_" + interface_function.getName()).str(), module);
  implementation_function->setCallingConv(interface_function.getCallingConv());
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
  sanitize_vm_implementation_attributes(*implementation_function,
                                        interface_function);
  return implementation_function;
}

llvm::APInt derive_vm_target_key(const llvm::Function &function,
                                 llvm::IntegerType *ptr_int_type);

llvm::APInt derive_vm_target_sentinel(const llvm::APInt &key);

llvm::GlobalVariable *get_or_create_vm_target_global(llvm::Function &function);

llvm::APInt derive_vm_target_seed_mask(const llvm::Function &function,
                                       llvm::IntegerType *ptr_int_type);

llvm::GlobalVariable *get_or_create_vm_target_seed_global(
    llvm::Function &interface_function, llvm::Function &implementation_function,
    llvm::IntegerType *ptr_int_type, std::uint32_t mba_depth);

llvm::Function *get_or_create_vm_target_seed_init_function(llvm::Module &module);

llvm::Function *get_or_create_vm_target_seed_resolver(llvm::Module &module,
                                                      llvm::IntegerType *ptr_int_type);

llvm::Function *get_or_create_vm_target_seed_case_resolver(
    llvm::Function &interface_function, llvm::Function &implementation_function,
    llvm::IntegerType *ptr_int_type, std::uint32_t mba_depth);

void ensure_vm_target_seed_resolver_case(llvm::Function &interface_function,
                                         llvm::Function &implementation_function,
                                         llvm::IntegerType *ptr_int_type,
                                         std::uint32_t mba_depth);

llvm::GlobalVariable *
get_or_create_vm_decode_key_global(llvm::Module &module,
                                   llvm::IntegerType *ptr_int_type,
                                   llvm::StringRef callee_name,
                                   const llvm::APInt &key);

llvm::Value *decode_virtualized_target_seed(
    llvm::IRBuilder<> &builder, llvm::Function &owner, llvm::StringRef prefix,
    llvm::GlobalVariable &target_seed_global, llvm::Value *opaque_key,
    const llvm::APInt &seed_mask, std::uint64_t seed_base,
    std::uint32_t mba_depth);

llvm::Value *decode_virtualized_integer_return(
    llvm::IRBuilder<> &builder, llvm::Function &owner,
    llvm::StringRef callee_name, llvm::Value *encoded_ret,
    llvm::Value *hidden_token, std::uint64_t token_seed,
    std::uint32_t mba_depth);

void rewrite_vm_interface_wrapper(llvm::Function &interface_function,
                                  llvm::Function &implementation_function,
                                  std::uint64_t wrapper_token,
                                  std::uint32_t mba_depth) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    llvm_unreachable("vm wrapper missing parent module");
  }

  llvm::GlobalVariable *target_global =
      get_or_create_vm_target_global(interface_function);
  if (target_global == nullptr) {
    llvm_unreachable("vm target cache global creation failed");
  }

  auto *ptr_int_type = llvm::cast<llvm::IntegerType>(target_global->getValueType());
  const llvm::APInt key = derive_vm_target_key(interface_function, ptr_int_type);
  const llvm::APInt sentinel = derive_vm_target_sentinel(key);
  llvm::GlobalVariable *target_seed_global = get_or_create_vm_target_seed_global(
      interface_function, implementation_function, ptr_int_type, mba_depth);
  if (target_seed_global == nullptr) {
    llvm_unreachable("vm target seed global creation failed");
  }

  llvm::GlobalVariable *decode_key_global = get_or_create_vm_decode_key_global(
      *module, ptr_int_type, interface_function.getName(), key);

  const std::uint64_t raw_salt =
      static_cast<std::uint64_t>(llvm::hash_value(interface_function.getName())) *
      0x9E3779B97F4A7C15ULL;
  const llvm::APInt salt(ptr_int_type->getBitWidth(),
                         raw_salt == 0 ? 0xC6EF3720ULL : raw_salt,
                         /*isSigned=*/false, /*implicitTrunc=*/true);

  interface_function.deleteBody();
  sanitize_vm_wrapper_attributes(interface_function);

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(
      interface_function.getContext(), "entry.obf.vm.wrapper",
      &interface_function);
  llvm::BasicBlock *resolve_bb = llvm::BasicBlock::Create(
      interface_function.getContext(),
      (interface_function.getName() + ".obf.wrapper.resolve").str(),
      &interface_function);
  llvm::BasicBlock *call_bb = llvm::BasicBlock::Create(
      interface_function.getContext(),
      (interface_function.getName() + ".obf.wrapper.call").str(),
      &interface_function);
  llvm::IRBuilder<> builder(entry);
  const std::string wrapper_prefix =
      (interface_function.getName() + ".obf.wrapper").str();
  llvm::Value *hidden_token = build_hidden_token_value(
      builder, interface_function, wrapper_prefix, wrapper_token,
      mba_depth, 0x6000ULL);

  auto *encoded_check = builder.CreateLoad(ptr_int_type, target_global,
                                           wrapper_prefix + ".check");
  auto *sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
  auto *is_unresolved = builder.CreateICmpEQ(encoded_check, sentinel_const,
                                             wrapper_prefix + ".unresolved");
  builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

  llvm::IRBuilder<> resolve_builder(resolve_bb);
  auto *resolve_key = resolve_builder.CreateLoad(ptr_int_type, decode_key_global,
                                                 wrapper_prefix + ".target.key");
  llvm::Value *target_int = decode_virtualized_target_seed(
      resolve_builder, interface_function, wrapper_prefix, *target_seed_global,
      resolve_key, derive_vm_target_seed_mask(interface_function, ptr_int_type),
      wrapper_token, mba_depth);
  llvm::Value *token_int = hidden_token;
  if (token_int->getType() != ptr_int_type) {
    token_int = resolve_builder.CreateZExtOrTrunc(token_int, ptr_int_type,
                                                  wrapper_prefix + ".token.cast");
  }

  token_int = mba::entangle_value(
      resolve_builder, token_int,
      mba::builder_context{.entropy_anchor =
                               mba::get_or_create_entropy_anchor(*module),
                           .seed_base = wrapper_token,
                           .depth = mba_depth},
      0x610000ULL + wrapper_token, wrapper_prefix + ".token");
  auto *salt_const = llvm::ConstantInt::get(ptr_int_type, salt);
  auto *runtime_key = resolve_builder.CreateXor(token_int, salt_const,
                                                wrapper_prefix + ".rkey");
  auto *mixed = resolve_builder.CreateXor(target_int, runtime_key,
                                          wrapper_prefix + ".mixed");
  auto *unmixed = resolve_builder.CreateXor(mixed, runtime_key,
                                            wrapper_prefix + ".unmixed");
  auto *key_const = llvm::ConstantInt::get(ptr_int_type, key);
  auto *new_encoded = resolve_builder.CreateXor(unmixed, key_const,
                                                wrapper_prefix + ".resolved");
  resolve_builder.CreateStore(new_encoded, target_global);
  resolve_builder.CreateBr(call_bb);

  llvm::IRBuilder<> call_builder(call_bb);
  auto *encoded_phi =
      call_builder.CreatePHI(ptr_int_type, 2, wrapper_prefix + ".encoded");
  encoded_phi->addIncoming(encoded_check, entry);
  encoded_phi->addIncoming(new_encoded, resolve_bb);

  auto *opaque_key = call_builder.CreateLoad(ptr_int_type, decode_key_global,
                                             wrapper_prefix + ".key");
  llvm::Value *decoded_target = mba::create_xor(
      call_builder, encoded_phi, opaque_key,
      mba::builder_context{.entropy_anchor =
                               mba::get_or_create_entropy_anchor(*module),
                           .seed_base = wrapper_token ^ key.getLimitedValue(),
                           .depth = mba_depth},
      0x620000ULL + wrapper_token, wrapper_prefix + ".decoded");
  llvm::Value *indirect_target = call_builder.CreateIntToPtr(
      decoded_target, implementation_function.getType(),
      wrapper_prefix + ".indirect");

  llvm::SmallVector<llvm::Value *, 8> arguments;
  arguments.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument &argument : interface_function.args()) {
    arguments.push_back(&argument);
  }
  arguments.push_back(hidden_token);

  auto *call = call_builder.CreateCall(
      implementation_function.getFunctionType(), indirect_target, arguments,
      interface_function.getReturnType()->isVoidTy()
          ? ""
          : wrapper_prefix + ".call");
  call->setCallingConv(interface_function.getCallingConv());
  call->setAttributes(build_vm_safe_callsite_attributes(implementation_function));
  if (interface_function.getReturnType()->isVoidTy()) {
    call_builder.CreateRetVoid();
  } else {
    llvm::Value *wrapper_ret = call;
    if (interface_function.getReturnType()->isIntegerTy()) {
      wrapper_ret = decode_virtualized_integer_return(
          call_builder, interface_function, interface_function.getName(), call,
          hidden_token, wrapper_token, mba_depth);
    }
    call_builder.CreateRet(wrapper_ret);
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

llvm::APInt derive_vm_target_sentinel(const llvm::APInt &key) {
  return ~key;
}

llvm::APInt derive_vm_target_seed_mask(const llvm::Function &function,
                                       llvm::IntegerType *ptr_int_type) {
  std::uint64_t mask_word =
      static_cast<std::uint64_t>(llvm::hash_value(function.getName()));
  mask_word = mix_vm_handshake_seed(
      mask_word,
      0x7c6ef372fe94f82aULL ^ static_cast<std::uint64_t>(ptr_int_type->getBitWidth()));
  return llvm::APInt(ptr_int_type->getBitWidth(),
                     mask_word == 0 ? 0x6a09e667f3bcc909ULL : mask_word,
                     /*isSigned=*/false, /*implicitTrunc=*/true);
}

llvm::GlobalVariable *get_or_create_vm_target_global(llvm::Function &function) {
  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const std::string global_name = ("__obf_vm_target_" + function.getName()).str();
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

llvm::GlobalVariable *get_or_create_vm_target_seed_global(
    llvm::Function &interface_function, llvm::Function &implementation_function,
    llvm::IntegerType *ptr_int_type, std::uint32_t mba_depth) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const std::string global_name =
      ("__obf_vm_targetseed_" + interface_function.getName()).str();
  if (llvm::GlobalVariable *existing = module->getNamedGlobal(global_name)) {
    ensure_vm_target_seed_resolver_case(interface_function, implementation_function,
                                        ptr_int_type, mba_depth);
    return existing;
  }

  auto *target_seed_global = new llvm::GlobalVariable(
      *module, ptr_int_type, false, llvm::GlobalValue::PrivateLinkage,
      llvm::ConstantInt::get(ptr_int_type, 0), global_name);
  target_seed_global->setDSOLocal(true);
  ensure_vm_target_seed_resolver_case(interface_function, implementation_function,
                                      ptr_int_type, mba_depth);

  llvm::Function *seed_init = get_or_create_vm_target_seed_init_function(*module);
  llvm::BasicBlock &entry_block = seed_init->getEntryBlock();
  llvm::IRBuilder<> builder(entry_block.getTerminator());

  llvm::Value *interface_int = builder.CreatePtrToInt(
      &interface_function, ptr_int_type, global_name + ".iface");
  llvm::Value *share_base = builder.CreateXor(
      interface_int,
      llvm::ConstantInt::get(ptr_int_type,
                             derive_vm_target_seed_mask(interface_function,
                                                         ptr_int_type)),
      global_name + ".base");
  builder.CreateStore(share_base, target_seed_global);
  return target_seed_global;
}

llvm::Function *get_or_create_vm_target_seed_init_function(llvm::Module &module) {
  constexpr llvm::StringRef init_name = "__obf_vm_seed_ctor";
  if (llvm::Function *existing = module.getFunction(init_name)) {
    return existing;
  }

  auto *init_type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(module.getContext()), false);
  auto *init_function = llvm::Function::Create(
      init_type, llvm::GlobalValue::PrivateLinkage, init_name, module);
  init_function->setDSOLocal(true);

  llvm::BasicBlock *entry = llvm::BasicBlock::Create(
      module.getContext(), "entry", init_function);
  llvm::IRBuilder<> builder(entry);
  builder.CreateRetVoid();
  llvm::appendToGlobalCtors(module, init_function, 0);
  return init_function;
}

llvm::Function *get_or_create_vm_target_seed_resolver(llvm::Module &module,
                                                      llvm::IntegerType *ptr_int_type) {
  constexpr llvm::StringRef resolver_name = "__obf_vm_seed_resolve";
  if (llvm::Function *existing = module.getFunction(resolver_name)) {
    return existing;
  }

  auto *resolver_type = llvm::FunctionType::get(
      ptr_int_type, {ptr_int_type, ptr_int_type}, /*isVarArg=*/false);
  auto *resolver = llvm::Function::Create(
      resolver_type, llvm::GlobalValue::PrivateLinkage, resolver_name, module);
  resolver->setDSOLocal(true);
  resolver->addFnAttr(llvm::Attribute::NoInline);

  auto arg_it = resolver->arg_begin();
  llvm::Argument *key_arg = &*arg_it++;
  llvm::Argument *base_arg = &*arg_it;
  key_arg->setName("obf.target.key");
  base_arg->setName("obf.share.base");

  llvm::BasicBlock *entry =
      llvm::BasicBlock::Create(module.getContext(), "entry", resolver);
  llvm::BasicBlock *miss =
      llvm::BasicBlock::Create(module.getContext(), "miss", resolver);
  llvm::IRBuilder<> entry_builder(entry);
  entry_builder.CreateSwitch(key_arg, miss);

  llvm::IRBuilder<> miss_builder(miss);
  miss_builder.CreateUnreachable();
  return resolver;
}

llvm::Function *get_or_create_vm_target_seed_case_resolver(
    llvm::Function &interface_function, llvm::Function &implementation_function,
    llvm::IntegerType *ptr_int_type, std::uint32_t mba_depth) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  const std::string resolver_name =
      ("__obf_vm_seedcase_" + interface_function.getName()).str();
  if (llvm::Function *existing = module->getFunction(resolver_name)) {
    return existing;
  }

  auto *resolver_type = llvm::FunctionType::get(
      ptr_int_type, {ptr_int_type, ptr_int_type}, /*isVarArg=*/false);
  auto *resolver = llvm::Function::Create(
      resolver_type, llvm::GlobalValue::PrivateLinkage, resolver_name, *module);
  resolver->setDSOLocal(true);
  resolver->addFnAttr(llvm::Attribute::NoInline);

  auto arg_it = resolver->arg_begin();
  llvm::Argument *key_arg = &*arg_it++;
  llvm::Argument *base_arg = &*arg_it;
  key_arg->setName("obf.target.key");
  base_arg->setName("obf.share.base");

  llvm::BasicBlock *entry =
      llvm::BasicBlock::Create(module->getContext(), "entry", resolver);
  llvm::IRBuilder<> builder(entry);
  const llvm::APInt key = derive_vm_target_key(interface_function, ptr_int_type);
  mba::builder_context resolve_context = mba::get_or_create_builder_context(
      *resolver, (interface_function.getName() + ".obf.seed").str(),
      key.getLimitedValue() ^ 0x63f000ULL);
  resolve_context.depth = mba_depth;

  llvm::Value *target_int = builder.CreatePtrToInt(
      &implementation_function, ptr_int_type,
      interface_function.getName() + ".obf.seed.target");
  llvm::Value *masked_target = mba::create_xor(
      builder, target_int, key_arg, resolve_context,
      0x63f100ULL + key.getLimitedValue(),
      (interface_function.getName() + ".obf.seed.target.masked").str());
  llvm::Value *resolved_target = mba::create_xor(
      builder, masked_target, key_arg, resolve_context,
      0x63f200ULL + key.getLimitedValue(),
      (interface_function.getName() + ".obf.seed.target.real").str());
  llvm::Value *share_value = mba::create_add(
      builder, resolved_target, base_arg, resolve_context,
      0x63f300ULL + key.getLimitedValue(),
      (interface_function.getName() + ".obf.seed.share").str());
  builder.CreateRet(share_value);
  return resolver;
}

void ensure_vm_target_seed_resolver_case(llvm::Function &interface_function,
                                         llvm::Function &implementation_function,
                                         llvm::IntegerType *ptr_int_type,
                                         std::uint32_t mba_depth) {
  llvm::Module *module = interface_function.getParent();
  if (module == nullptr) {
    return;
  }

  llvm::Function *resolver =
      get_or_create_vm_target_seed_resolver(*module, ptr_int_type);
  auto *dispatch = llvm::dyn_cast<llvm::SwitchInst>(
      resolver->getEntryBlock().getTerminator());
  if (dispatch == nullptr) {
    llvm_unreachable("vm seed resolver missing dispatch switch");
  }

  const llvm::APInt key = derive_vm_target_key(interface_function, ptr_int_type);
  auto *key_const = llvm::ConstantInt::get(ptr_int_type, key);
  llvm::Function *case_resolver = get_or_create_vm_target_seed_case_resolver(
      interface_function, implementation_function, ptr_int_type, mba_depth);
  if (case_resolver == nullptr) {
    return;
  }
  for (const auto &entry : dispatch->cases()) {
    if (entry.getCaseValue()->getValue() == key) {
      return;
    }
  }

  llvm::BasicBlock *case_block = llvm::BasicBlock::Create(
      module->getContext(), (interface_function.getName() + ".obf.seed.case").str(),
      resolver, dispatch->getDefaultDest());
  dispatch->addCase(llvm::cast<llvm::ConstantInt>(key_const), case_block);

  llvm::IRBuilder<> builder(case_block);
  llvm::Argument *key_arg = resolver->getArg(0);
  llvm::Argument *base_arg = resolver->getArg(1);
  llvm::Value *share_value = builder.CreateCall(
      case_resolver->getFunctionType(), case_resolver, {key_arg, base_arg},
      (interface_function.getName() + ".obf.seed.share").str());
  builder.CreateRet(share_value);
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

llvm::Value *decode_virtualized_target_seed(
    llvm::IRBuilder<> &builder, llvm::Function &owner, llvm::StringRef prefix,
    llvm::GlobalVariable &target_seed_global, llvm::Value *opaque_key,
    const llvm::APInt &seed_mask, std::uint64_t seed_base,
    std::uint32_t mba_depth) {
  auto *ptr_int_type =
      llvm::cast<llvm::IntegerType>(target_seed_global.getValueType());
  auto *encoded_base = builder.CreateLoad(ptr_int_type, &target_seed_global,
                                          prefix.str() + ".target.seed.base");
  mba::builder_context decode_context{.entropy_anchor =
                                          mba::get_or_create_entropy_anchor(
                                              *owner.getParent()),
                                      .seed_base = seed_base ^
                                                   seed_mask.getLimitedValue(),
                                      .depth = mba_depth};
  llvm::Value *masked_base = mba::create_xor(
      builder, encoded_base, opaque_key, decode_context,
      0x604000ULL + seed_base, prefix.str() + ".target.base.masked");
  llvm::Value *real_base = mba::create_xor(
      builder, masked_base, opaque_key, decode_context,
      0x605000ULL + seed_base, prefix.str() + ".target.base");
  llvm::Function *resolver =
      get_or_create_vm_target_seed_resolver(*owner.getParent(), ptr_int_type);
  auto *share_value = builder.CreateCall(
      resolver->getFunctionType(), resolver, {opaque_key, real_base},
      prefix.str() + ".target.seed.value");
  llvm::Value *masked_value = mba::create_xor(
      builder, share_value, opaque_key, decode_context,
      0x606000ULL + seed_base, prefix.str() + ".target.value.masked");
  llvm::Value *real_value = mba::create_xor(
      builder, masked_value, opaque_key, decode_context,
      0x607000ULL + seed_base, prefix.str() + ".target.value");
  return builder.CreateSub(real_value, real_base, prefix.str() + ".real.int");
}

llvm::Value *decode_virtualized_integer_return(
    llvm::IRBuilder<> &builder, llvm::Function &owner,
    llvm::StringRef callee_name, llvm::Value *encoded_ret,
    llvm::Value *hidden_token, std::uint64_t token_seed,
    std::uint32_t mba_depth) {
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
      mba::builder_context{.entropy_anchor =
                               mba::get_or_create_entropy_anchor(*module),
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
  llvm::GlobalVariable *target_seed_global = get_or_create_vm_target_seed_global(
      function, implementation_function, ptr_int_type, mba_depth);
  if (target_seed_global == nullptr) {
    return false;
  }

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

    llvm::GlobalVariable *decode_key_global = get_or_create_vm_decode_key_global(
        *module, ptr_int_type, function.getName(), key);

    llvm::BasicBlock *orig_bb = call->getParent();
    llvm::BasicBlock *call_bb = orig_bb->splitBasicBlock(
        call->getIterator(), (function.getName() + ".obf.call").str());
    orig_bb->getTerminator()->eraseFromParent();

    llvm::BasicBlock *resolve_bb = llvm::BasicBlock::Create(
        module->getContext(), (function.getName() + ".obf.resolve").str(),
        caller, call_bb);

    llvm::IRBuilder<> entry_builder(orig_bb);
    llvm::Value *hidden_token = build_hidden_token_value(
        entry_builder, *caller, (function.getName() + ".obf.call").str(),
        site.hidden_token, mba_depth,
        0x700000ULL + static_cast<std::uint64_t>(callsite_index++));
    auto *encoded_check = entry_builder.CreateLoad(
        ptr_int_type, target_global, function.getName() + ".obf.check");
    auto *sentinel_const = llvm::ConstantInt::get(ptr_int_type, sentinel);
    auto *is_unresolved = entry_builder.CreateICmpEQ(
        encoded_check, sentinel_const, function.getName() + ".obf.unresolved");
    entry_builder.CreateCondBr(is_unresolved, resolve_bb, call_bb);

    llvm::IRBuilder<> resolve_builder(resolve_bb);
    auto *resolve_key = resolve_builder.CreateLoad(
        ptr_int_type, decode_key_global, function.getName() + ".obf.target.key");
    llvm::Value *target_int = decode_virtualized_target_seed(
        resolve_builder, *caller, function.getName(), *target_seed_global,
        resolve_key, derive_vm_target_seed_mask(function, ptr_int_type),
        site.hidden_token, mba_depth);
    llvm::Value *token_int = hidden_token;
    if (token_int->getType() != ptr_int_type) {
      token_int = resolve_builder.CreateZExtOrTrunc(
          token_int, ptr_int_type, function.getName() + ".obf.token.cast");
    }
    const std::string token_name = (function.getName() + ".obf.token").str();
    token_int = mba::entangle_value(
        resolve_builder, token_int,
        mba::builder_context{.entropy_anchor =
                                 mba::get_or_create_entropy_anchor(*module),
                             .seed_base = site.hidden_token,
                             .depth = mba_depth},
        0x710000ULL + site.hidden_token, token_name);
    auto *salt_const = llvm::ConstantInt::get(ptr_int_type, salt);
    auto *runtime_key = resolve_builder.CreateXor(
        token_int, salt_const, function.getName() + ".obf.rkey");
    auto *mixed = resolve_builder.CreateXor(target_int, runtime_key,
                                            function.getName() + ".obf.mixed");
    auto *unmixed = resolve_builder.CreateXor(mixed, runtime_key,
                                              function.getName() + ".obf.unmixed");
    auto *key_const = llvm::ConstantInt::get(ptr_int_type, key);
    auto *new_encoded = resolve_builder.CreateXor(
        unmixed, key_const, function.getName() + ".obf.resolved");
    resolve_builder.CreateStore(new_encoded, target_global);
    resolve_builder.CreateBr(call_bb);

    llvm::IRBuilder<> call_builder(call);
    auto *encoded_phi =
        call_builder.CreatePHI(ptr_int_type, 2, function.getName() + ".obf.encoded");
    encoded_phi->addIncoming(encoded_check, orig_bb);
    encoded_phi->addIncoming(new_encoded, resolve_bb);

    auto *opaque_key = call_builder.CreateLoad(
        ptr_int_type, decode_key_global, function.getName() + ".obf.key");
    llvm::Value *decoded_target = mba::create_xor(
        call_builder, encoded_phi, opaque_key,
        mba::builder_context{.entropy_anchor =
                                 mba::get_or_create_entropy_anchor(*module),
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
    rewritten_call->setAttributes(
        build_vm_safe_callsite_attributes(implementation_function));

    llvm::Type *call_ret_type = rewritten_call->getType();
    if (call_ret_type->isIntegerTy()) {
      llvm::IRBuilder<> decode_builder(call);
      llvm::Value *decoded_ret = decode_virtualized_integer_return(
          decode_builder, *caller, function.getName(), rewritten_call,
          hidden_token, site.hidden_token, mba_depth);

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

} // namespace

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
               const protection_level *only_level) {
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
                                                 .report =
                                                     target_candidate.state->report};
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
        binding.implementation_function->setDSOLocal(true);
        rewrite_vm_interface_wrapper(*binding.interface_function,
                                     *binding.implementation_function,
                                     binding.wrapper_token, config.mba.depth);
        virtualized_functions[target_function->getName()] = std::move(binding);
        skip_functions.insert(target_function->getName());
      }
    }
  }

  return virtualized_functions;
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

void include_vm_parent_functions(
    llvm::StringSet<> &virtualized_names,
    const virtualized_function_map &virtualized_functions) {
  for (const auto &entry : virtualized_functions) {
    const function_pipeline_state *state = entry.second.state;
    if (state == nullptr || state->function == nullptr) {
      continue;
    }

    if (entry.getKey() == state->function->getName()) {
      virtualized_names.insert(state->function->getName());
    }
  }
}

} // namespace obf
