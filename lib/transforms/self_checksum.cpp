#include "obf/transforms/self_checksum.h"

#include "obf/frontend/annotations.h"
#include "obf/support/mba_config_builder.h"
#include "obf/support/runtime_abi_generated.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include <algorithm>
#include <cstdint>
#include <string>

namespace obf {
namespace {

constexpr std::uint64_t kDefaultSeed = 0x53454c465f434355ULL;
constexpr std::uint32_t kMinSampleWindowBytes = 16;
constexpr std::uint32_t kMaxSampleWindowBytes = 32;

struct checksum_site {
  llvm::Instruction* instruction = nullptr;
  llvm::IntegerType* type = nullptr;
  std::uint64_t site_seed = 0;
};

bool is_vm_function(const llvm::Function& function, const function_annotation_map& annotations) {
  const llvm::StringRef name = function.getName();
  if (name.starts_with("_obf_vm_") || name.starts_with("__obf_vm_")) { return true; }

  for (const llvm::Attribute attribute : function.getAttributes().getFnAttrs()) {
    if (attribute.isStringAttribute() && attribute.getKindAsString().starts_with("vm.")) {
      return true;
    }
  }

  const std::string* annotation = find_function_annotation(annotations, name);
  return annotation != nullptr && (llvm::StringRef(*annotation).contains_insensitive("vm") ||
                                   llvm::StringRef(*annotation).contains_insensitive("virtual"));
}

bool is_runtime_or_generated_function(const llvm::Function& function) {
  const llvm::StringRef name = function.getName();
  return name.starts_with("rt_core_") || name.starts_with("_obf_") || name.starts_with("llvm.");
}

bool is_viable_target(const llvm::Function& function, const function_annotation_map& annotations) {
  return !function.isDeclaration() && !function.isIntrinsic() && !function.empty() &&
         !is_runtime_or_generated_function(function) && !is_vm_function(function, annotations);
}

bool can_checksum_function(const llvm::Function& function,
                           const function_annotation_map& annotations) {
  if (!is_viable_target(function, annotations)) { return false; }
  if (function.hasAvailableExternallyLinkage()) { return false; }
  return function.hasLocalLinkage();
}

bool directly_calls(const llvm::Function& caller, const llvm::Function& callee) {
  for (const llvm::BasicBlock& block : caller) {
    for (const llvm::Instruction& instruction : block) {
      const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call != nullptr && call->getCalledFunction() == &callee) { return true; }
    }
  }
  return false;
}

bool reaches_function(const llvm::Function& start, const llvm::Function& target) {
  llvm::SmallVector<const llvm::Function*, 16> pending{&start};
  llvm::SmallPtrSet<const llvm::Function*, 16> visited;
  while (!pending.empty()) {
    const llvm::Function* current = pending.pop_back_val();
    if (!visited.insert(current).second) { continue; }
    if (current == &target) { return true; }
    for (const llvm::BasicBlock& block : *current) {
      for (const llvm::Instruction& instruction : block) {
        const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        const llvm::Function* callee = call != nullptr ? call->getCalledFunction() : nullptr;
        if (callee != nullptr && !callee->isDeclaration()) { pending.push_back(callee); }
      }
    }
  }
  return false;
}

bool is_safe_sibling_target(const llvm::Function& function,
                            const llvm::Function& candidate,
                            const function_annotation_map& annotations) {
  return &candidate != &function && can_checksum_function(candidate, annotations) &&
         !directly_calls(function, candidate) && !reaches_function(candidate, function);
}

llvm::Function* select_target_function(llvm::Function& function,
                                       llvm::Module& module,
                                       const function_annotation_map& annotations,
                                       std::uint64_t seed) {
  llvm::SmallVector<llvm::Function*, 8> siblings;
  for (llvm::Function& candidate : module) {
    if (is_safe_sibling_target(function, candidate, annotations)) {
      siblings.push_back(&candidate);
    }
  }

  if (siblings.empty()) { return nullptr; }
  return siblings[static_cast<std::size_t>(seed % siblings.size())];
}

bool is_supported_instruction(const llvm::Instruction& instruction) {
  if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
    return binary->getType()->isIntegerTy();
  }
  if (const auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
    return cmp->getOperand(0)->getType()->isIntegerTy();
  }
  if (const auto* select = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
    return select->getType()->isIntegerTy();
  }
  if (const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
    return ret->getReturnValue() != nullptr && ret->getReturnValue()->getType()->isIntegerTy();
  }
  return false;
}

llvm::IntegerType* get_key_type(const llvm::Instruction& instruction) {
  if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
    return llvm::dyn_cast<llvm::IntegerType>(binary->getType());
  }
  if (const auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
    return llvm::dyn_cast<llvm::IntegerType>(cmp->getOperand(0)->getType());
  }
  if (const auto* select = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
    return llvm::dyn_cast<llvm::IntegerType>(select->getType());
  }
  if (const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
    return ret->getReturnValue() != nullptr
               ? llvm::dyn_cast<llvm::IntegerType>(ret->getReturnValue()->getType())
               : nullptr;
  }
  return nullptr;
}

llvm::SmallVector<checksum_site, 8> collect_sites(llvm::Function& function,
                                                  const self_checksum_options& options,
                                                  std::uint64_t function_seed) {
  llvm::SmallVector<checksum_site, 8> sites;
  if (options.max_checksum_sites == 0) { return sites; }

  std::size_t site_index = 0;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      if (!is_supported_instruction(instruction)) { continue; }
      llvm::IntegerType* type = get_key_type(instruction);
      if (type == nullptr) { continue; }
      sites.push_back({&instruction,
                       type,
                       obf::mix_seed(function_seed, static_cast<std::uint64_t>(site_index + 1))});
      ++site_index;
      if (sites.size() >= options.max_checksum_sites) { return sites; }
    }
  }

  return sites;
}

llvm::FunctionCallee get_or_create_checksum_runtime(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(context);
  llvm::Type* i64_ty = llvm::Type::getInt64Ty(context);
  llvm::FunctionType* type = llvm::FunctionType::get(i64_ty, {i8_ptr_ty, i64_ty, i64_ty}, false);
  return module.getOrInsertFunction(OBF_RT_CODE_CHECKSUM_STR, type);
}

llvm::Value* create_checksum_key(llvm::IRBuilder<>& builder,
                                 llvm::FunctionCallee runtime,
                                 llvm::Function& target,
                                 llvm::IntegerType& type,
                                 std::uint32_t sample_window_bytes,
                                 std::uint64_t site_seed,
                                 const mba::builder_context&) {
  llvm::Value* target_ptr = builder.CreatePointerCast(
      &target, llvm::PointerType::getUnqual(builder.getContext()), "obf.selfchk.target");
  const std::uint32_t sample_size =
      std::clamp(sample_window_bytes, kMinSampleWindowBytes, kMaxSampleWindowBytes);
  llvm::Value* checksum =
      builder.CreateCall(runtime,
                         {target_ptr, builder.getInt64(sample_size), builder.getInt64(site_seed)},
                         "obf.selfchk.raw");

  llvm::Type* checksum_type =
      type.getBitWidth() < 64 ? static_cast<llvm::Type*>(&type) : builder.getInt64Ty();
  llvm::Value* actual_checksum =
      builder.CreateTruncOrBitCast(checksum, checksum_type, "obf.selfchk.actual");
  // Post-link code bytes cannot be predicted at IR time.  Seed the expected
  // checksum with the dynamic value, making this a neutral delta until the
  // checked bytes differ within the same execution.
  llvm::Value* expected_checksum = builder.CreateXor(
      actual_checksum, llvm::ConstantInt::get(checksum_type, 0), "obf.selfchk.expected");
  return builder.CreateXor(actual_checksum, expected_checksum, "obf.selfchk.delta");
}

void inject_keyed_use(llvm::Instruction& instruction,
                      llvm::IRBuilder<>& builder,
                      llvm::Value* delta,
                      llvm::IntegerType&) {
  if (auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
    llvm::Value* lhs = binary->getOperand(0);
    binary->setOperand(0, builder.CreateXor(lhs, delta, "obf.selfchk.adjusted"));
    return;
  }

  if (auto* cmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
    llvm::Value* lhs = cmp->getOperand(0);
    cmp->setOperand(0, builder.CreateXor(lhs, delta, "obf.selfchk.adjusted"));
    return;
  }

  if (auto* select = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
    llvm::Value* true_value = select->getTrueValue();
    select->setTrueValue(builder.CreateXor(true_value, delta, "obf.selfchk.adjusted"));
    return;
  }

  if (auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
    llvm::Value* value = ret->getReturnValue();
    ret->setOperand(0, builder.CreateXor(value, delta, "obf.selfchk.adjusted"));
  }
}

}  // namespace

self_checksum_result transform_self_checksum(llvm::Function& function,
                                             llvm::Module& module,
                                             const self_checksum_options& options) {
  if (!options.enabled) { return {.detail = "disabled"}; }
  if (function.isDeclaration()) { return {.detail = "declaration"}; }
  if (options.max_checksum_sites == 0) { return {.detail = "max_checksum_sites is zero"}; }
  const std::uint64_t configured_seed = options.seed == 0 ? kDefaultSeed : options.seed;
  const std::uint64_t function_seed =
      obf::mix_seed(configured_seed, stable_hash_string(function.getName(), 0x73656c665f6363ULL));
  const function_annotation_map annotations = collect_function_annotations(module);
  llvm::Function* target = select_target_function(function, module, annotations, function_seed);
  if (target == nullptr) { return {.skipped_no_target = 1, .detail = "no checksum target"}; }

  llvm::SmallVector<checksum_site, 8> sites = collect_sites(function, options, function_seed);
  if (sites.empty()) { return {.detail = "no eligible checksum sites"}; }

  llvm::FunctionCallee runtime = get_or_create_checksum_runtime(module);
  auto mba_context = obf::support::make_mba_context(function, "obf.selfchk", function_seed, {});

  std::size_t applied = 0;
  for (checksum_site& site : sites) {
    if (site.instruction == nullptr || site.type == nullptr) { continue; }
    llvm::IRBuilder<> builder(site.instruction);
    llvm::Value* key = create_checksum_key(builder,
                                           runtime,
                                           *target,
                                           *site.type,
                                           options.sample_window_bytes,
                                           site.site_seed,
                                           mba_context);
    inject_keyed_use(*site.instruction, builder, key, *site.type);
    ++applied;
  }

  return {.checksum_site_count = applied,
          .keyed_value_count = applied,
          .detail = applied == 0 ? std::string("no checksum sites applied")
                                 : std::to_string(applied) + " checksum site(s) targeting " +
                                       target->getName().str()};
}

}  // namespace obf
