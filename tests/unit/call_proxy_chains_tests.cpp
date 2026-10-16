#include "obf/transforms/call_proxy_chains.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <iostream>

namespace {
int failures = 0;
void expect(bool condition, const char* message) {
  if (!condition) {
    ++failures;
    std::cerr << "[fail] " << message << '\n';
  }
}

struct fixture {
  llvm::LLVMContext context;
  llvm::Module module{"proxy.chains", context};
  llvm::Function* target;
  llvm::Function* owner;
  llvm::CallInst* source;
  obf::live_proxy_site_registry sites;
  obf::proxy_contract_registry contracts;
  obf::call_proxy_options options;
  explicit fixture(bool tail = false) {
    module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
    module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
    auto* type = llvm::FunctionType::get(
        llvm::Type::getInt64Ty(context), {llvm::Type::getInt64Ty(context)}, false);
    target = llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, "target", module);
    owner = llvm::Function::Create(type, llvm::GlobalValue::InternalLinkage, "owner", module);
    llvm::IRBuilder<> b(llvm::BasicBlock::Create(context, "entry", owner));
    source = b.CreateCall(target, {owner->getArg(0)});
    if (tail) source->setTailCallKind(llvm::CallInst::TCK_MustTail);
    b.CreateRet(source);
    sites.register_selected_owner(*owner, 0x123456789, false);
    sites.discover_native_sites(module);
    options.enabled = true;
    options.min_hops = options.max_hops = 2;
    options.coverage_policy = obf::proxy_coverage_policy::best_effort;
  }
  obf::proxy_stage_result emit() {
    return obf::apply_call_proxy_chain_stage(module, options, sites, contracts);
  }
};

void test_stateful_and_effects() {
  fixture f;
  f.owner->setMemoryEffects(llvm::MemoryEffects::none());
  f.owner->addFnAttr(llvm::Attribute::Speculatable);
  auto* parent = llvm::Function::Create(
      f.owner->getFunctionType(), llvm::GlobalValue::InternalLinkage, "parent", f.module);
  llvm::IRBuilder<> b(llvm::BasicBlock::Create(f.context, "entry", parent));
  auto* incoming = b.CreateCall(f.owner, {parent->getArg(0)});
  incoming->setMemoryEffects(llvm::MemoryEffects::none());
  incoming->addFnAttr(llvm::Attribute::Speculatable);
  b.CreateRet(incoming);
  parent->setMemoryEffects(llvm::MemoryEffects::none());
  const auto result = f.emit();
  expect(result.changed && result.exact.sites == 1 && result.exact.nodes == 4,
         "two protected stateful hops require one terminal bridge and one exact target checker");
  const auto& contract = f.contracts.contracts.front();
  auto* entry = llvm::cast<llvm::CallInst>(static_cast<llvm::Value*>(contract.entry));
  auto* slot = llvm::cast<llvm::AllocaInst>(static_cast<llvm::Value*>(contract.context));
  expect(entry->isNoTailCall() && entry->arg_size() == 2 && slot->isStaticAlloca() &&
             slot->getParent() == &f.owner->getEntryBlock(),
         "stateful entry keeps its caller frame and one fixed entry-block slot");
  unsigned initializers = 0;
  for (llvm::Instruction& i : llvm::instructions(*f.owner))
    if (auto* store = llvm::dyn_cast<llvm::StoreInst>(&i))
      if (auto* gep = llvm::dyn_cast<llvm::GetElementPtrInst>(store->getPointerOperand()))
        if (gep->getPointerOperand() == slot) ++initializers;
  expect(initializers == 14, "caller initializes all fields, including all zero sentinels");
  expect(!f.owner->doesNotAccessMemory() && !parent->doesNotAccessMemory() &&
             !incoming->doesNotAccessMemory() &&
             !incoming->hasFnAttr(llvm::Attribute::Speculatable),
         "entropy and checks invalidate incoming effects through direct callers");
  expect(!llvm::verifyModule(f.module, &llvm::errs()),
         "stateful route must satisfy LLVM verification");
}

void test_equivalent_single_route_dispatch() {
  fixture f;
  f.emit();
  unsigned replacements = 0;
  for (llvm::Function& helper : f.module) {
    if (!obf::is_call_proxy_helper(helper)) continue;
    auto* dispatch = llvm::dyn_cast<llvm::SwitchInst>(helper.getEntryBlock().getTerminator());
    if (!dispatch || dispatch->getNumCases() != 1) continue;
    const auto one_case = *dispatch->case_begin();
    llvm::IRBuilder<> builder(dispatch);
    builder.CreateCondBr(builder.CreateICmpEQ(dispatch->getCondition(), one_case.getCaseValue()),
                         one_case.getCaseSuccessor(),
                         dispatch->getDefaultDest());
    dispatch->eraseFromParent();
    ++replacements;
  }
  expect(replacements == 2, "fixture normalizes both sole-route hop switches as LLVM LTO does");
  obf::validate_live_proxy_contracts(
      f.module, f.contracts, obf::proxy_platform_contract_for(f.module));
  expect(!llvm::verifyModule(f.module, &llvm::errs()),
         "equivalent finite route dispatch remains valid LLVM IR");
}

void test_target_checker_lto_guard_transport() {
  fixture f;
  f.contracts.reserve_lto_guards = true;
  const auto before = f.emit();
  expect(before.exact.pending_lto_guard_instructions == before.exact.nodes + 1,
         "prelink charges one future guard per generated helper and distinct protected live owner");
  for (llvm::Function& helper : f.module) {
    if (!obf::is_call_proxy_helper(helper) && !helper.hasFnAttribute("obf.lto.proxy.contract"))
      continue;
    helper.addFnAttr("obf.lto.finalize", "1");
    helper.addFnAttr(llvm::Attribute::NoInline);
    helper.addFnAttr(llvm::Attribute::OptimizeNone);
    auto* guard_type =
        llvm::FunctionType::get(llvm::Type::getVoidTy(f.context), {helper.getType()}, false);
    auto guard = f.module.getOrInsertFunction("__obf_lto_finalize_required", guard_type);
    llvm::IRBuilder<> b(&*helper.getEntryBlock().getFirstInsertionPt());
    b.CreateCall(guard, {&helper});
  }
  obf::validate_live_proxy_contracts(
      f.module, f.contracts, obf::proxy_platform_contract_for(f.module));
  obf::proxy_contract_registry recovered;
  obf::recover_call_proxy_contracts(f.module, recovered, f.options);
  expect(recovered.exact.pending_lto_guard_instructions == 0 &&
             recovered.exact.added_instructions ==
                 before.exact.added_instructions + before.exact.nodes + 1,
         "materialized guards replace their pending charges without changing the combined resource "
         "total");
  expect(!llvm::verifyModule(f.module, &llvm::errs()),
         "mandatory LTO self-address guards pin every helper without changing the validated "
         "comparison bodies");
}

void test_abi_only_and_admission() {
  fixture f(true);
  const auto original = f.owner->getFunctionType();
  const auto result = f.emit();
  expect(result.changed && result.exact.nodes == 2 && result.exact.context_bytes == 0,
         "original musttail route has no context or ordinary terminal bridge");
  const auto& contract = f.contracts.contracts.front();
  auto* entry = llvm::cast<llvm::CallInst>(static_cast<llvm::Value*>(contract.entry));
  expect(entry->isMustTailCall() && entry->getFunctionType() == original,
         "original musttail entry retains the exact signature");
  auto* terminal = llvm::cast<llvm::Function>(static_cast<llvm::Value*>(contract.terminal));
  bool found_indirect = false;
  for (llvm::Instruction& i : llvm::instructions(*terminal))
    if (auto* call = llvm::dyn_cast<llvm::CallInst>(&i))
      found_indirect |= call->isMustTailCall() && !call->getCalledFunction();
  expect(found_indirect, "ABI-only terminal remains an indirect musttail transfer");
  expect(!llvm::verifyModule(f.module, &llvm::errs()),
         "ABI-only route must satisfy LLVM verification");

  fixture rejected(true);
  rejected.options.mode_policy = obf::proxy_mode_policy::stateful_only;
  const auto admission = obf::analyze_proxy_site(rejected.sites.sites().front(),
                                                 obf::proxy_platform_contract_for(rejected.module),
                                                 rejected.options);
  expect(!admission.admitted && admission.code == "stateful_requires_live_caller",
         "stateful-only mode rejects original musttail instead of weakening its route");
}

void test_exact_retained_caps() {
  fixture f;
  f.emit();
  auto* other = llvm::Function::Create(
      f.owner->getFunctionType(), llvm::GlobalValue::InternalLinkage, "fresh", f.module);
  llvm::IRBuilder<> b(llvm::BasicBlock::Create(f.context, "entry", other));
  auto* call = b.CreateCall(f.target, {other->getArg(0)});
  b.CreateRet(call);
  obf::live_proxy_site_registry fresh;
  fresh.register_selected_owner(*other, 0x4321, false);
  fresh.discover_native_sites(f.module);
  const auto admission = obf::analyze_proxy_site(
      fresh.sites().front(), obf::proxy_platform_contract_for(f.module), f.options);
  const obf::admitted_proxy_site admitted{fresh.sites().front(), admission};
  auto exact_nodes = f.options;
  exact_nodes.max_nodes_per_module = f.contracts.exact.nodes;
  const auto node_plan = obf::plan_call_proxy_chains(f.module, {admitted}, exact_nodes);
  expect(node_plan.routes.empty() && node_plan.events.size() == 1 &&
             node_plan.events.front().code == "budget_max_nodes_per_module" &&
             !node_plan.events.front().required,
         "exact retained node cap rejects only the fresh best-effort site");
  auto exact_ir = f.options;
  exact_ir.max_added_ir_instructions = f.contracts.exact.added_instructions;
  const auto ir_plan = obf::plan_call_proxy_chains(f.module, {admitted}, exact_ir);
  expect(ir_plan.routes.empty() && ir_plan.events.size() == 1 &&
             ir_plan.events.front().code == "budget_max_added_ir_instructions",
         "exact retained instruction cap remains valid and records the fresh rejection");
  auto one_past = f.options;
  one_past.max_nodes_per_module = f.contracts.exact.nodes + 4;
  const auto fits = obf::plan_call_proxy_chains(f.module, {admitted}, one_past);
  expect(fits.routes.size() == 1,
         "a complete fresh route fits at the exact combined node reservation");
}

void test_same_owner_clone_recovery(bool abi_only) {
  fixture f(abi_only);
  f.emit();
  llvm::ValueToValueMapTy map;
  auto* clone = llvm::CloneFunction(f.owner, map);
  clone->setName("clone");
  auto* combined = llvm::Function::Create(
      f.owner->getFunctionType(), llvm::GlobalValue::InternalLinkage, "combined", f.module);
  llvm::IRBuilder<> b(llvm::BasicBlock::Create(f.context, "entry", combined));
  llvm::CallInst* first;
  llvm::CallInst* second;
  if (abi_only) {
    auto* left = llvm::BasicBlock::Create(f.context, "left", combined);
    auto* right = llvm::BasicBlock::Create(f.context, "right", combined);
    b.CreateCondBr(b.CreateICmpEQ(combined->getArg(0), b.getInt64(0)), left, right);
    b.SetInsertPoint(left);
    first = b.CreateCall(f.owner, {combined->getArg(0)});
    first->setTailCallKind(llvm::CallInst::TCK_MustTail);
    b.CreateRet(first);
    b.SetInsertPoint(right);
    second = b.CreateCall(clone, {combined->getArg(0)});
    second->setTailCallKind(llvm::CallInst::TCK_MustTail);
    b.CreateRet(second);
  } else {
    first = b.CreateCall(f.owner, {combined->getArg(0)});
    second = b.CreateCall(clone, {first});
    b.CreateRet(second);
  }
  llvm::InlineFunctionInfo info;
  expect(llvm::InlineFunction(*first, info).isSuccess(),
         "first protected owner clone must inline in the fixture");
  expect(llvm::InlineFunction(*second, info).isSuccess(),
         "second protected owner clone must inline in the fixture");
  f.owner->eraseFromParent();
  clone->eraseFromParent();
  obf::proxy_contract_registry recovered;
  obf::recover_call_proxy_contracts(f.module, recovered, f.options);
  expect(recovered.contracts.size() == 2 &&
             recovered.contracts[0].route.source.site.identity.instance_id !=
                 recovered.contracts[1].route.source.site.identity.instance_id,
         "two protected copies in one owner receive distinct deterministic live instances");
  obf::validate_live_proxy_contracts(
      f.module, recovered, obf::proxy_platform_contract_for(f.module));
  expect(!llvm::verifyModule(f.module, &llvm::errs()),
         "recovered same-owner clones remain valid LLVM IR");
}
void test_structured_vm_thunk_is_not_excluded(bool reject_nonidentity_mask = false) {
  llvm::LLVMContext context;
  llvm::Module module("proxy.vm.admission", context);
  module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
  module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
  auto* i32 = llvm::Type::getInt32Ty(context);
  auto* i64 = llvm::Type::getInt64Ty(context);
  auto* source_type = llvm::FunctionType::get(i32, false);
  auto* thunk_type = llvm::FunctionType::get(i32, {i64}, false);
  auto* wrapper =
      llvm::Function::Create(source_type, llvm::GlobalValue::ExternalLinkage, "wrapper", module);
  auto* thunk = llvm::Function::Create(
      thunk_type, llvm::GlobalValue::InternalLinkage, "__obf_vm_e_admission", module);
  thunk->setDSOLocal(true);
  thunk->addFnAttr("obf.vm.entry.thunk");
  llvm::IRBuilder<> thunk_body(llvm::BasicBlock::Create(context, "entry", thunk));
  thunk_body.CreateRet(thunk_body.CreateTrunc(thunk->getArg(0), i32));
  auto* resolver_type = llvm::FunctionType::get(thunk->getType(), {i64}, false);
  auto* resolver =
      llvm::Function::Create(resolver_type, llvm::GlobalValue::InternalLinkage, "resolver", module);
  llvm::IRBuilder<llvm::NoFolder> resolver_body(
      llvm::BasicBlock::Create(context, "entry", resolver));
  auto* neutral = resolver_body.CreateXor(resolver->getArg(0), resolver->getArg(0));
  resolver_body.CreateRet(resolver_body.CreateIntToPtr(
      resolver_body.CreateXor(resolver_body.CreatePtrToInt(thunk, i64), neutral),
      thunk->getType()));
  auto* resolver_seed = new llvm::GlobalVariable(module,
                                                 i64,
                                                 false,
                                                 llvm::GlobalValue::PrivateLinkage,
                                                 llvm::ConstantInt::get(i64, 53),
                                                 "resolver.seed");
  auto* owner =
      llvm::Function::Create(source_type, llvm::GlobalValue::InternalLinkage, "vm_caller", module);
  llvm::IRBuilder<llvm::NoFolder> b(llvm::BasicBlock::Create(context, "entry", owner));
  auto* original = b.CreateCall(wrapper);
  auto* token_base = b.CreateAdd(b.getInt64(17), b.getInt64(0));
  auto* token = b.CreateAnd(token_base, b.getInt64(-1));
  auto* seed_load = b.CreateLoad(i64, resolver_seed);
  auto* target = b.CreateCall(resolver_type, resolver, {seed_load});
  auto* replacement = b.CreateCall(thunk_type, target, {token});
  auto* key = new llvm::GlobalVariable(
      module, i64, true, llvm::GlobalValue::InternalLinkage, b.getInt64(29), "return.key");
  auto* decoded =
      b.CreateXor(replacement, b.CreateTrunc(b.CreateXor(b.CreateLoad(i64, key), token), i32));
  b.CreateRet(decoded);
  obf::live_proxy_site_registry sites;
  obf::live_proxy_site site;
  site.binding = {41, 43, 47, "binding", true};
  site.replacement_call = replacement;
  site.decoded_target = target;
  site.hidden_token_operand = token;
  site.encoded_result = replacement;
  site.return_decode_root = decoded;
  site.expected_target = thunk;
  site.original_site_token = 17;
  site.decision_seed = 53;
  site.required = true;
  site.effective_abi = obf::make_proxy_abi_descriptor(*replacement);
  site.return_contract = {obf::vm_result_role::encoded_integer, 47, 17, 32, "return.key"};
  sites.register_rewrite(*original, site);
  original->eraseFromParent();
  obf::call_proxy_options options;
  options.enabled = true;
  options.min_hops = options.max_hops = 2;
  auto native = sites.sites().front();
  native.is_vm = false;
  const auto native_admission =
      obf::analyze_proxy_site(native, obf::proxy_platform_contract_for(module), options);
  expect(!native_admission.admitted && native_admission.code == "infrastructure",
         "the exact structured VM thunk exception must not admit native infrastructure calls");
  obf::proxy_contract_registry contracts;
  contracts.reserve_lto_guards = true;
  std::uint64_t original_instructions = 0;
  for (const llvm::Function& function : module)
    original_instructions += function.getInstructionCount();
  const auto result = obf::apply_call_proxy_chain_stage(module, options, sites, contracts);
  expect(
      result.changed && contracts.contracts.size() == 1 && result.events.size() == 1 &&
          result.events.front().protected_site,
      "a registered exact VM entry thunk must emit protection instead of an infrastructure skip");
  expect(seed_load->isVolatile() && resolver->hasFnAttribute("obf.lto.proxy.dependency") &&
             contracts.contracts.front().route.source.admission.dependencies.size() == 1 &&
             result.exact.nodes == 5,
         "exact local resolver and existing global input load have owned bounded preservation "
         "obligations");
  std::uint64_t emitted_instructions = 0;
  for (const llvm::Function& function : module)
    emitted_instructions += function.getInstructionCount();
  expect(result.exact.added_instructions == emitted_instructions - original_instructions + 1,
         "gross added IR excludes the unchanged pre-existing resolver body and does not subtract "
         "the erased source call");
  expect(result.exact.pending_lto_guard_instructions == result.exact.nodes + 1,
         "prelink reserves one guard per unique mesh/dependency function and one per distinct live "
         "owner");
  if (reject_nonidentity_mask) {
    llvm::cast<llvm::Instruction>(token)->setOperand(1, b.getInt64(-2));
    obf::validate_live_proxy_contracts(module, contracts, obf::proxy_platform_contract_for(module));
    expect(false, "a nonidentity token mask must fail retained contract validation");
    return;
  }
  token->replaceAllUsesWith(token_base);
  llvm::cast<llvm::Instruction>(token)->eraseFromParent();
  obf::validate_live_proxy_contracts(module, contracts, obf::proxy_platform_contract_for(module));
  resolver->setName("renamed.resolver");
  resolver_seed->setName("renamed.resolver.seed");
  bool volatile_key = false;
  for (llvm::Instruction& i : llvm::instructions(*owner))
    if (auto* load = llvm::dyn_cast<llvm::LoadInst>(&i))
      if (load->getPointerOperand() == key) volatile_key |= load->isVolatile();
  expect(volatile_key,
         "proxy retains the existing caller-bound VM return-key load as volatile without adding a "
         "decode");
  key->setName("renamed.return.key");
  obf::proxy_contract_registry recovered;
  obf::recover_call_proxy_contracts(module, recovered, options);
  expect(recovered.contracts.size() == 1 &&
             recovered.contracts.front().route.source.site.return_contract.key_global_name ==
                 key->getName(),
         "retained VM key identity resolves independently of the artifact-renamed symbol");
  expect(!llvm::verifyModule(module, &llvm::errs()),
         "structured VM route must satisfy LLVM verification");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 2 && llvm::StringRef(argv[1]) == "--reject-nonidentity-mask") {
    test_structured_vm_thunk_is_not_excluded(true);
    return 2;
  }
  test_stateful_and_effects();
  test_equivalent_single_route_dispatch();
  test_target_checker_lto_guard_transport();
  test_abi_only_and_admission();
  test_exact_retained_caps();
  test_structured_vm_thunk_is_not_excluded();
  test_same_owner_clone_recovery(false);
  test_same_owner_clone_recovery(true);
  if (failures) return 1;
  std::cout << "[ok] call_proxy_chains_tests passed\n";
  return 0;
}
