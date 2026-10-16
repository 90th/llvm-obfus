#include "obf/transforms/call_proxy_sites.h"
#include "obf/transforms/call_proxy_chains.h"
#include "obf/support/runtime_abi_generated.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <iostream>

namespace {
int failures = 0;
void expect(bool condition, const char* message) {
  if (!condition) {
    ++failures;
    std::cerr << "[fail] " << message << '\n';
  }
}
bool has_issue(const std::vector<obf::proxy_site_issue>& issues, llvm::StringRef code) {
  return std::any_of(
      issues.begin(), issues.end(), [&](const auto& issue) { return issue.code == code; });
}

struct native_fixture {
  llvm::LLVMContext context;
  llvm::Module module{"proxy.registry.native", context};
  obf::live_proxy_site_registry registry;
  llvm::Function* target;
  llvm::Function* owner;
  llvm::CallInst* call;
  native_fixture() {
    module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
    module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
    auto* type = llvm::FunctionType::get(llvm::Type::getInt32Ty(context), false);
    target = llvm::Function::Create(type, llvm::GlobalValue::ExternalLinkage, "target", module);
    owner = llvm::Function::Create(type, llvm::GlobalValue::InternalLinkage, "owner", module);
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", owner));
    call = builder.CreateCall(target);
    builder.CreateRet(call);
    registry.register_selected_owner(*owner, 0x1234, true);
    registry.discover_native_sites(module);
  }
};

struct vm_fixture {
  llvm::LLVMContext context;
  llvm::Module module{"proxy.registry.vm", context};
  obf::live_proxy_site_registry registry;
  llvm::Function* owner;
  llvm::Function* wrapper;
  llvm::Function* thunk;
  llvm::CallInst* replacement;
  llvm::Value* token;
  llvm::Value* target;
  llvm::Instruction* decode;
  llvm::WeakTrackingVH old_call_handle;
  vm_fixture() {
    module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
    module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
    auto* i32 = llvm::Type::getInt32Ty(context);
    auto* i64 = llvm::Type::getInt64Ty(context);
    auto* original_type = llvm::FunctionType::get(i32, false);
    auto* thunk_type = llvm::FunctionType::get(i32, {i64}, false);
    wrapper = llvm::Function::Create(
        original_type, llvm::GlobalValue::ExternalLinkage, "wrapper", module);
    thunk = llvm::Function::Create(thunk_type, llvm::GlobalValue::InternalLinkage, "thunk", module);
    thunk->setDSOLocal(true);
    thunk->addFnAttr(llvm::Attribute::NoInline);
    thunk->addFnAttr("obf.vm.entry.thunk");
    owner =
        llvm::Function::Create(original_type, llvm::GlobalValue::InternalLinkage, "caller", module);
    llvm::IRBuilder<llvm::NoFolder> builder(llvm::BasicBlock::Create(context, "entry", owner));
    auto* original = builder.CreateCall(wrapper);
    old_call_handle = original;
    token = builder.CreateAdd(builder.getInt64(17), builder.getInt64(0), "token");
    auto* address = builder.CreatePtrToInt(thunk, i64);
    target = builder.CreateIntToPtr(address, thunk->getType(), "decoded.target");
    replacement = builder.CreateCall(thunk_type, target, {token});
    auto* key = new llvm::GlobalVariable(
        module, i64, true, llvm::GlobalValue::InternalLinkage, builder.getInt64(29), "return.key");
    auto* bound_key = builder.CreateXor(builder.CreateLoad(i64, key), token);
    auto* narrowed_key = builder.CreateTrunc(bound_key, i32);
    decode = llvm::cast<llvm::Instruction>(builder.CreateXor(replacement, narrowed_key, "decode"));
    builder.CreateRet(decode);
    obf::vm_rewritten_site site;
    site.binding = {41, 43, 47, "binding", true};
    site.replacement_call = replacement;
    site.decoded_target = target;
    site.hidden_token_operand = token;
    site.encoded_result = replacement;
    site.return_decode_root = decode;
    site.expected_target = thunk;
    site.original_site_token = 17;
    site.decision_seed = 53;
    site.required = true;
    site.effective_abi = obf::make_proxy_abi_descriptor(*replacement);
    site.return_contract = {obf::vm_result_role::encoded_integer, 47, 17, 32, "return.key"};
    registry.register_rewrite(*original, std::move(site));
    original->eraseFromParent();
  }
};

void test_native_owned_discovery_and_exclusions() {
  native_fixture fixture;
  expect(fixture.registry.sites().size() == 1,
         "selected native call must have one owned live record");
  expect(fixture.registry.validate().empty(), "fresh native record must validate");
  const auto identity = fixture.registry.sites().front().identity;
  expect(identity.module_id != 0 && identity.owner_id != 0 && identity.site_id != 0 &&
             identity.instance_id != 0,
         "source identity components must be explicit and nonzero");
  native_fixture identical;
  expect(identical.registry.sites().front().identity == identity,
         "source IDs must be deterministic, not allocation based");
  expect(fixture.registry.sites().front().decision_seed == 0x1234 &&
             fixture.registry.sites().front().required,
         "policy and seed snapshots must remain owned");
  auto* helper = llvm::Function::Create(fixture.target->getFunctionType(),
                                        llvm::GlobalValue::ExternalLinkage,
                                        "__obf_auth_runtime",
                                        fixture.module);
  expect(obf::is_call_proxy_infrastructure(*helper),
         "runtime/authentication helper is infrastructure");
  expect(!obf::is_call_proxy_infrastructure(*fixture.target),
         "unsupported ordinary user functions are not infrastructure");
  auto* configured_runtime = llvm::Function::Create(fixture.target->getFunctionType(),
                                                    llvm::GlobalValue::ExternalLinkage,
                                                    OBF_RT_CODE_CHECKSUM_STR,
                                                    fixture.module);
  expect(obf::is_call_proxy_infrastructure(*configured_runtime),
         "configured generated runtime ABI symbol must be excluded independently of the default "
         "prefix");
  const std::string middle_name = std::string("user_") + OBF_RT_ABI_PREFIX_STR + "ordinary_target";
  auto* ordinary_with_middle_prefix = llvm::Function::Create(fixture.target->getFunctionType(),
                                                             llvm::GlobalValue::ExternalLinkage,
                                                             middle_name,
                                                             fixture.module);
  expect(!obf::is_call_proxy_infrastructure(*ordinary_with_middle_prefix),
         "a runtime prefix appearing inside an ordinary user name is not the reserved runtime "
         "namespace");
  llvm::IRBuilder<> builder(fixture.call);
  auto* generated = builder.CreateCall(fixture.target);
  fixture.registry.discover_native_sites(fixture.module);
  expect(fixture.registry.sites().size() == 1,
         "unmarked generated calls must not acquire invented user provenance");
  generated->eraseFromParent();
}

void test_missing_and_noncall_rauw_are_visible() {
  {
    native_fixture fixture;
    fixture.call->replaceAllUsesWith(llvm::ConstantInt::get(fixture.call->getType(), 0));
    expect(has_issue(fixture.registry.validate(), "missing_live_call"),
           "tracking RAUW to noncall must not count as live coverage");
    expect(has_issue(fixture.registry.rebuild(fixture.module), "noncall_rauw"),
           "metadata alone must not silently repair noncall RAUW");
  }
  {
    native_fixture fixture;
    for (auto& use : llvm::make_early_inc_range(fixture.call->uses())) {
      use.set(llvm::ConstantInt::get(fixture.call->getType(), 0));
    }
    fixture.call->eraseFromParent();
    expect(has_issue(fixture.registry.rebuild(fixture.module), "unproved_site_removal"),
           "null old call in a live owner requires an explicit dead proof");
  }
}

void test_replace_move_clone_and_rebuild() {
  native_fixture fixture;
  const auto source = fixture.registry.sites().front();
  llvm::IRBuilder<> builder(fixture.call);
  auto* replacement = builder.CreateCall(fixture.target);
  auto updated = source;
  updated.replacement_call = replacement;
  updated.encoded_result = replacement;
  fixture.registry.replace_site(source.identity, updated);
  for (auto& use : llvm::make_early_inc_range(fixture.call->uses())) { use.set(replacement); }
  fixture.call->eraseFromParent();
  fixture.call = replacement;
  expect(fixture.registry.validate().empty(), "explicit replacement must survive original erasure");

  auto* moved_owner = llvm::Function::Create(fixture.owner->getFunctionType(),
                                             llvm::GlobalValue::InternalLinkage,
                                             "outlined",
                                             fixture.module);
  auto* block = fixture.call->getParent();
  block->removeFromParent();
  block->insertInto(moved_owner);
  fixture.registry.move_site(source.identity, *moved_owner);
  expect(fixture.registry.sites().front().identity.owner_id == source.identity.owner_id,
         "movement must retain original source ownership");
  expect(fixture.registry.validate().empty(), "explicit moved owner must validate");

  auto* clone_owner = llvm::Function::Create(fixture.owner->getFunctionType(),
                                             llvm::GlobalValue::InternalLinkage,
                                             "cloned",
                                             fixture.module);
  llvm::IRBuilder<> clone_builder(llvm::BasicBlock::Create(fixture.context, "entry", clone_owner));
  auto* cloned_call = llvm::cast<llvm::CallInst>(fixture.call->clone());
  clone_builder.Insert(cloned_call);
  clone_builder.CreateRet(cloned_call);
  expect(fixture.registry.rebuild(fixture.module).empty(),
         "complete cloned call metadata must support validated rebuild");
  expect(fixture.registry.sites().size() == 2, "rebuild must enumerate every live clone");
  const auto& first = fixture.registry.sites()[0].identity;
  const auto& second = fixture.registry.sites()[1].identity;
  expect(first.site_id == second.site_id && first.owner_id == second.owner_id &&
             first.instance_id != second.instance_id,
         "clones share source identity but have distinct deterministic instance IDs");
  expect(fixture.registry.rebuild(fixture.module).empty() && fixture.registry.sites().size() == 2,
         "rebuild must be idempotent and not duplicate instances");
}

void test_proven_dead_and_dead_owner() {
  {
    native_fixture fixture;
    const auto identity = fixture.registry.sites().front().identity;
    auto* dead_block = llvm::BasicBlock::Create(fixture.context, "unreachable", fixture.owner);
    auto* result = fixture.owner->getEntryBlock().getTerminator();
    result->setOperand(0, llvm::ConstantInt::get(fixture.call->getType(), 0));
    fixture.call->removeFromParent();
    llvm::IRBuilder<> builder(dead_block);
    builder.Insert(fixture.call);
    builder.CreateUnreachable();
    const auto proof = fixture.registry.prove_dead_site(identity);
    fixture.call->eraseFromParent();
    fixture.registry.erase_dead_site(identity, proof);
    expect(fixture.registry.rebuild(fixture.module).empty() &&
               fixture.registry.sites().front().dead,
           "unreachable call and protection obligation can be discharged with matching proof");
  }
  {
    native_fixture fixture;
    fixture.owner->eraseFromParent();
    expect(fixture.registry.rebuild(fixture.module).empty() &&
               fixture.registry.sites().front().dead,
           "whole-owner deletion proves that no live protection obligation remains");
  }
}

void test_vm_explicit_target_token_and_encoded_result() {
  vm_fixture fixture;
  expect(fixture.old_call_handle == nullptr,
         "old VM call handle must actually be erased in this fixture");
  expect(fixture.registry.validate().empty(),
         "erased old handle cannot lose new VM replacement coverage");
  const auto saved = fixture.registry.sites().front();
  expect(saved.decoded_target == fixture.replacement->getCalledOperand() &&
             saved.hidden_token_operand == fixture.token &&
             saved.encoded_result == fixture.replacement &&
             saved.return_decode_root == fixture.decode && saved.binding.no_cache,
         "registry must expose the exact resolver/token/result/decode/no-cache handoff");
  fixture.replacement->setArgOperand(
      0, llvm::ConstantInt::get(llvm::Type::getInt64Ty(fixture.context), 18));
  expect(has_issue(fixture.registry.validate(), "wrong_hidden_token"),
         "different same-typed token is not the registered token");
  expect(!fixture.registry.rebuild(fixture.module).empty(),
         "rebuild cannot invent proof for a substituted constant token");
  fixture.replacement->setArgOperand(0, fixture.token);
  fixture.registry.sites().front() = saved;
  fixture.registry.sites().front().return_contract.binding_id++;
  expect(has_issue(fixture.registry.validate(), "wrong_return_binding"),
         "return decode must belong to the exact binding");
  fixture.registry.sites().front() = saved;
  fixture.registry.sites().front().encoded_result = fixture.decode;
  expect(has_issue(fixture.registry.validate(), "wrong_result_role"),
         "caller decode cannot replace encoded-result role");
  fixture.registry.sites().front() = saved;
  fixture.registry.sites().front().owner_function = fixture.wrapper;
  expect(has_issue(fixture.registry.validate(), "wrong_live_owner"),
         "unrelated same-module owner is not valid provenance");
  fixture.registry.sites().front() = saved;
  fixture.decode->setMetadata("obf.call.proxy.roles", nullptr);
  expect(has_issue(fixture.registry.validate(), "missing_decode_role"),
         "return association requires an explicit decode role");
}

void test_vm_clone_and_result_bypass() {
  vm_fixture fixture;
  llvm::IRBuilder<> builder(fixture.owner->getEntryBlock().getTerminator());
  auto* call = llvm::cast<llvm::CallInst>(fixture.replacement->clone());
  builder.Insert(call);
  auto* decode = fixture.decode->clone();
  decode->replaceUsesOfWith(fixture.replacement, call);
  builder.Insert(decode);
  expect(fixture.registry.rebuild(fixture.module).empty() && fixture.registry.sites().size() == 2,
         "VM clone rebuild must match each call to its own complete decode association");
  auto* bypass = builder.CreateAdd(call, builder.getInt32(1));
  (void)bypass;
  expect(has_issue(fixture.registry.validate(), "bypassed_return_decode"),
         "an extra encoded-result use outside the original decode is a contract violation");
}

void test_vm_void_and_unencoded_result_roles() {
  for (bool is_void : {true, false}) {
    llvm::LLVMContext context;
    llvm::Module module("proxy.registry.result", context);
    module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
    module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
    auto* result_type = is_void ? llvm::Type::getVoidTy(context) : llvm::Type::getDoubleTy(context);
    auto* original_type = llvm::FunctionType::get(result_type, false);
    auto* thunk_type =
        llvm::FunctionType::get(result_type, {llvm::Type::getInt64Ty(context)}, false);
    auto* wrapper = llvm::Function::Create(
        original_type, llvm::GlobalValue::ExternalLinkage, "wrapper", module);
    auto* thunk =
        llvm::Function::Create(thunk_type, llvm::GlobalValue::ExternalLinkage, "thunk", module);
    auto* owner =
        llvm::Function::Create(original_type, llvm::GlobalValue::InternalLinkage, "caller", module);
    llvm::IRBuilder<llvm::NoFolder> builder(llvm::BasicBlock::Create(context, "entry", owner));
    auto* original = builder.CreateCall(wrapper);
    auto* token = builder.getInt64(17);
    auto* target = builder.CreateIntToPtr(builder.CreatePtrToInt(thunk, builder.getInt64Ty()),
                                          thunk->getType());
    auto* replacement = builder.CreateCall(thunk_type, target, {token});
    if (is_void) {
      builder.CreateRetVoid();
    } else {
      builder.CreateRet(replacement);
    }
    obf::vm_rewritten_site site;
    site.binding = {41, 43, 47, "binding", false};
    site.replacement_call = replacement;
    site.decoded_target = target;
    site.hidden_token_operand = token;
    site.encoded_result = replacement;
    site.expected_target = thunk;
    site.original_site_token = 17;
    site.effective_abi = obf::make_proxy_abi_descriptor(*replacement);
    site.return_contract = {is_void ? obf::vm_result_role::void_result
                                    : obf::vm_result_role::unchanged_result,
                            47,
                            17,
                            0,
                            ""};
    obf::live_proxy_site_registry registry;
    registry.register_rewrite(*original, std::move(site));
    original->eraseFromParent();
    expect(registry.validate().empty(),
           "void and unencoded VM results must validate without an invented decode");
    expect(registry.sites().front().return_decode_root == nullptr &&
               registry.sites().front().encoded_result == replacement,
           "void/unchanged result roles must point to the exact replacement call");
    registry.replace_value(
        registry.sites().front().identity, obf::proxy_value_role::hidden_token, *token);
    expect(registry.validate().empty(),
           "explicit unchanged-token update preserves exact constant bits and result roles");
  }
}

void test_typed_abi_payload_and_original_tail() {
  native_fixture fixture;
  auto* i32 = llvm::Type::getInt32Ty(fixture.context);
  auto* pair = llvm::StructType::get(i32, i32);
  auto* ptr = llvm::PointerType::get(fixture.context, 0);
  auto* abi_type =
      llvm::FunctionType::get(llvm::Type::getVoidTy(fixture.context), {i32, ptr}, false);
  auto* abi_target = llvm::Function::Create(
      abi_type, llvm::GlobalValue::ExternalLinkage, "sret.target", fixture.module);
  auto* abi_owner = llvm::Function::Create(
      abi_type, llvm::GlobalValue::InternalLinkage, "sret.owner", fixture.module);
  llvm::IRBuilder<> builder(llvm::BasicBlock::Create(fixture.context, "entry", abi_owner));
  auto* call = builder.CreateCall(abi_target, {abi_owner->getArg(0), abi_owner->getArg(1)});
  call->addParamAttr(1, llvm::Attribute::getWithStructRetType(fixture.context, pair));
  call->addParamAttr(1, llvm::Attribute::getWithAlignment(fixture.context, llvm::Align(8)));
  builder.CreateRetVoid();
  const auto abi = obf::make_proxy_abi_descriptor(*call);
  expect(obf::proxy_abi_matches(*call, abi),
         "typed sret at nonzero position must have a complete ABI description");
  call->removeParamAttr(1, llvm::Attribute::StructRet);
  call->addParamAttr(1, llvm::Attribute::getWithStructRetType(fixture.context, i32));
  expect(!obf::proxy_abi_matches(*call, abi),
         "ABI comparison must reject changed typed payload, not merely compare attribute kinds");

  fixture.call->setTailCallKind(llvm::CallInst::TCK_MustTail);
  obf::live_proxy_site_registry tail_registry;
  obf::live_proxy_site tail;
  tail.binding = {1, 2, 3, "tail.binding", true};
  tail.expected_target = fixture.target;
  tail.effective_abi = obf::make_proxy_abi_descriptor(*fixture.call);
  tail.return_contract.role = obf::vm_result_role::unchanged_result;
  tail.return_contract.binding_id = tail.binding.binding_id;
  tail_registry.register_preserved_musttail(*fixture.call, tail);
  expect(tail_registry.validate().empty(),
         "preserved VM original-musttail wrapper has an independent exact-ABI record");
  expect(tail_registry.sites().front().hidden_token_operand == nullptr &&
             tail_registry.sites().front().return_decode_root == nullptr,
         "original-musttail wrapper must not acquire a hidden token or caller decode");
}

void test_preserved_vm_obligation_without_selected_caller() {
  native_fixture fixture;
  obf::live_proxy_site_registry preserved;
  preserved.register_selected_owner(*fixture.target, 19, true);
  obf::live_proxy_site site;
  site.binding = {1, 2, 3, "preserved.binding", false};
  site.expected_target = fixture.target;
  site.effective_abi = obf::make_proxy_abi_descriptor(*fixture.call);
  site.preserved_unsupported = true;
  site.preservation_reason = "preserved_vm_abi_mismatch";
  site.return_contract.role = obf::vm_result_role::unchanged_result;
  site.return_contract.binding_id = site.binding.binding_id;
  preserved.register_preserved_site(*fixture.call, site);
  preserved.discover_native_sites(fixture.module);
  expect(!preserved.owner_selected(*fixture.owner) && preserved.sites().size() == 1,
         "selected VM binding must retain unsupported incoming boundary even when its caller is "
         "not selected");
  expect(
      preserved.sites().front().preserved_unsupported &&
          preserved.sites().front().preservation_reason == "preserved_vm_abi_mismatch",
      "unsupported preserved VM boundary must have an explicit consumer-visible rejection reason");
  expect(preserved.validate().empty() && preserved.rebuild(fixture.module).empty(),
         "preserved unsupported VM record retains exact original ABI and wrapper without token or "
         "decode");
  const auto admission = obf::analyze_proxy_site(preserved.sites().front(),
                                                 obf::proxy_platform_contract_for(fixture.module),
                                                 obf::call_proxy_options{});
  expect(!admission.admitted && admission.code == "preserved_vm_abi_mismatch",
         "consumer admission must explicitly reject preserved unsupported VM boundaries rather "
         "than lose their coverage obligation");

  native_fixture strict_source;
  obf::live_proxy_site_registry strict_registry;
  strict_registry.register_selected_owner(*strict_source.owner, 23, true);
  site.required = false;
  site.expected_target = strict_source.target;
  site.effective_abi = obf::make_proxy_abi_descriptor(*strict_source.call);
  strict_registry.register_preserved_site(*strict_source.call, site);
  expect(strict_registry.sites().front().required,
         "VM preserved handoff must not discard the owned original source owner's required "
         "coverage policy");
}

obf::proxy_admission admission_for(native_fixture& fixture) {
  auto site = fixture.registry.sites().front();
  site.effective_abi = obf::make_proxy_abi_descriptor(*fixture.call);
  return obf::analyze_proxy_site(
      site, obf::proxy_platform_contract_for(fixture.module), obf::call_proxy_options{});
}

void test_admission_rejects_unqualified_hardening() {
  {
    native_fixture fixture;
    expect(admission_for(fixture).admitted,
           "ordinary scalar admission control must be admitted before hardening changes");
  }
  for (llvm::StringRef flag : {"CFI Canonical Jump Tables", "Cross-DSO CFI", "kcfi"}) {
    native_fixture fixture;
    fixture.module.addModuleFlag(llvm::Module::Warning, flag, 1U);
    const auto platform = obf::proxy_platform_contract_for(fixture.module);
    const auto admission = admission_for(fixture);
    expect(!platform.terminal_hardening && !admission.admitted &&
               admission.code == "unsupported_hardening",
           "actual CFI/KCFI module contracts must reject unqualified terminal forwarding");
  }
  {
    native_fixture fixture;
    auto* signature = llvm::ConstantAsMetadata::get(
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(fixture.context), 0x1234));
    fixture.call->setMetadata(llvm::LLVMContext::MD_kcfi_type,
                              llvm::MDNode::get(fixture.context, {signature}));
    const auto admission = admission_for(fixture);
    expect(!admission.admitted && admission.code == "unsupported_hardening",
           "actual KCFI call type metadata must not disappear through proxy admission");
  }
  for (bool on_owner : {true, false}) {
    native_fixture fixture;
    (on_owner ? fixture.owner : fixture.target)->addFnAttr(llvm::Attribute::SanitizeMemory);
    const auto admission = admission_for(fixture);
    expect(!admission.admitted && admission.code == "unsupported_hardening",
           "MSan ABI on either participating function must reject an unqualified noundef "
           "forwarding builder");
  }
}

void test_admission_rejects_bundles_and_special_semantics() {
  {
    native_fixture fixture;
    llvm::IRBuilder<> builder(fixture.call);
    llvm::OperandBundleDef bundle("deopt", llvm::ArrayRef<llvm::Value*>{});
    auto* bundled = builder.CreateCall(fixture.target, {}, {bundle});
    auto site = fixture.registry.sites().front();
    site.replacement_call = bundled;
    site.encoded_result = bundled;
    site.effective_abi = obf::make_proxy_abi_descriptor(*bundled);
    const auto admission = obf::analyze_proxy_site(
        site, obf::proxy_platform_contract_for(fixture.module), obf::call_proxy_options{});
    expect(!admission.admitted && admission.code == "operand_bundle",
           "a real call operand bundle requires rejection rather than silent stripping");
  }
  for (auto attribute :
       {llvm::Attribute::ReturnsTwice, llvm::Attribute::Convergent, llvm::Attribute::NoDuplicate}) {
    native_fixture fixture;
    fixture.call->addFnAttr(attribute);
    const auto admission = admission_for(fixture);
    expect(!admission.admitted && admission.code == "special_semantics",
           "unsupported call-level special semantics must reject admission before attribute "
           "rebuilding");
  }
  for (bool on_owner : {true, false}) {
    for (auto attribute :
         {llvm::Attribute::ReturnsTwice, llvm::Attribute::Convergent, llvm::Attribute::Naked}) {
      native_fixture fixture;
      (on_owner ? fixture.owner : fixture.target)->addFnAttr(attribute);
      const auto admission = admission_for(fixture);
      expect(
          !admission.admitted && admission.code == "special_semantics",
          "unsupported owner/target special semantics must not be repaired by dropping attributes");
    }
  }
}

void test_admission_typed_byval_alignment_and_unknown_abi() {
  llvm::LLVMContext context;
  llvm::Module module("proxy.admission.byval", context);
  module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
  module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
  auto* i32 = llvm::Type::getInt32Ty(context);
  auto* i64 = llvm::Type::getInt64Ty(context);
  auto* payload = llvm::StructType::get(i64, i64);
  auto* different_payload = llvm::StructType::get(i32, i32);
  auto* signature = llvm::FunctionType::get(i32, {llvm::PointerType::get(context, 0)}, false);
  auto* target =
      llvm::Function::Create(signature, llvm::GlobalValue::ExternalLinkage, "target", module);
  auto* owner =
      llvm::Function::Create(signature, llvm::GlobalValue::InternalLinkage, "owner", module);
  llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", owner));
  auto* call = builder.CreateCall(target, {owner->getArg(0)});
  builder.CreateRet(call);
  const auto original_byval = llvm::Attribute::getWithByValType(context, payload);
  const auto original_align = llvm::Attribute::getWithAlignment(context, llvm::Align(8));
  target->addParamAttr(0, original_byval);
  target->addParamAttr(0, original_align);
  call->addParamAttr(0, original_byval);
  call->addParamAttr(0, original_align);
  obf::live_proxy_site site;
  site.owner_function = owner;
  site.replacement_call = call;
  site.decoded_target = target;
  site.expected_target = target;
  site.encoded_result = call;
  const auto admission = [&] {
    site.effective_abi = obf::make_proxy_abi_descriptor(*call);
    return obf::analyze_proxy_site(
        site, obf::proxy_platform_contract_for(module), obf::call_proxy_options{});
  };
  expect(admission().admitted,
         "exact matching typed byval and alignment admission control must be admitted");
  const auto original_abi = obf::make_proxy_abi_descriptor(*call);
  call->removeParamAttr(0, llvm::Attribute::ByVal);
  call->addParamAttr(0, llvm::Attribute::getWithByValType(context, different_payload));
  const auto payload_rejection = admission();
  expect(!payload_rejection.admitted && payload_rejection.code == "abi_payload_mismatch" &&
             !obf::proxy_abi_matches(*call, original_abi),
         "same byval attribute kind with different payload type/size must reject actual consumer "
         "admission");
  call->removeParamAttr(0, llvm::Attribute::ByVal);
  call->addParamAttr(0, original_byval);
  call->removeParamAttr(0, llvm::Attribute::Alignment);
  call->addParamAttr(0, llvm::Attribute::getWithAlignment(context, llvm::Align(4)));
  const auto alignment_rejection = admission();
  expect(!alignment_rejection.admitted && alignment_rejection.code == "abi_payload_mismatch" &&
             !obf::proxy_abi_matches(*call, original_abi),
         "typed byval explicit alignment mismatch must reject rather than weaken the forwarding "
         "contract");
  call->removeParamAttr(0, llvm::Attribute::Alignment);
  call->addParamAttr(0, original_align);
  call->addParamAttr(0, llvm::Attribute::get(context, "unqualified-parameter-abi", "v1"));
  const auto unknown_rejection = admission();
  expect(!unknown_rejection.admitted && unknown_rejection.code == "unsupported_abi_attribute",
         "new unqualified parameter ABI contract must reject actual admission instead of being "
         "silently stripped");
  call->removeParamAttr(0, "unqualified-parameter-abi");
  call->removeParamAttr(0, llvm::Attribute::ByVal);
  target->removeParamAttr(0, llvm::Attribute::ByVal);
  const auto byref = llvm::Attribute::getWithByRefType(context, payload);
  call->addParamAttr(0, byref);
  target->addParamAttr(0, byref);
  const auto byref_rejection = admission();
  expect(!byref_rejection.admitted && byref_rejection.code == "unsupported_abi_attribute",
         "matching typed byref still requires an unsupported ABI rejection, not attribute-kind "
         "forwarding");
}

void test_admission_exact_vm_thunk_does_not_disable_helper_exclusion() {
  vm_fixture vm;
  vm.thunk->setName("__obf_vm_e_registry_admission");
  const auto admission = obf::analyze_proxy_site(vm.registry.sites().front(),
                                                 obf::proxy_platform_contract_for(vm.module),
                                                 obf::call_proxy_options{});
  expect(admission.admitted && admission.target == vm.thunk,
         "an explicitly registered VM binding must admit its exact generated thunk rather than "
         "silently treating it as infrastructure");
  vm.thunk->removeFnAttr("obf.vm.entry.thunk");
  const auto unproved = obf::analyze_proxy_site(vm.registry.sites().front(),
                                                obf::proxy_platform_contract_for(vm.module),
                                                obf::call_proxy_options{});
  expect(!unproved.admitted && unproved.code == "infrastructure",
         "a VM-looking symbol without the genuine entry-thunk producer role must remain excluded");
  native_fixture native;
  native.target->setName("__obf_auth_runtime");
  const auto excluded = admission_for(native);
  expect(!excluded.admitted && excluded.code == "infrastructure",
         "structured VM thunk admission must not disable ordinary authentication/runtime helper "
         "exclusion");
}

void test_windows_byval_qualification_preserves_nonzero_sret() {
  for (auto convention : {llvm::CallingConv::C, llvm::CallingConv::Fast}) {
    llvm::LLVMContext context;
    llvm::Module module("proxy.admission.windows.byval", context);
    module.setTargetTriple(llvm::Triple("x86_64-pc-windows-msvc"));
    module.setDataLayout(
        "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128");
    auto* i64 = llvm::Type::getInt64Ty(context);
    auto* ptr = llvm::PointerType::get(context, 0);
    auto* payload = llvm::StructType::get(i64, i64, i64);
    auto* signature =
        llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i64, ptr, ptr}, false);
    auto* target =
        llvm::Function::Create(signature, llvm::GlobalValue::ExternalLinkage, "target", module);
    auto* owner =
        llvm::Function::Create(signature, llvm::GlobalValue::InternalLinkage, "owner", module);
    target->setCallingConv(convention);
    owner->setCallingConv(convention);
    const auto sret = llvm::Attribute::getWithStructRetType(context, payload);
    const auto byval = llvm::Attribute::getWithByValType(context, payload);
    const auto alignment = llvm::Attribute::getWithAlignment(context, llvm::Align(8));
    for (auto* function : {target, owner}) {
      function->addParamAttr(1, sret);
      function->addParamAttr(1, alignment);
      function->addParamAttr(2, byval);
      function->addParamAttr(2, alignment);
    }
    llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", owner));
    auto* call = builder.CreateCall(target, {owner->getArg(0), owner->getArg(1), owner->getArg(2)});
    call->setCallingConv(convention);
    call->addParamAttr(1, sret);
    call->addParamAttr(1, alignment);
    call->addParamAttr(2, byval);
    call->addParamAttr(2, alignment);
    builder.CreateRetVoid();
    obf::live_proxy_site site;
    site.owner_function = owner;
    site.replacement_call = call;
    site.decoded_target = target;
    site.expected_target = target;
    site.encoded_result = call;
    const auto platform = obf::proxy_platform_contract_for(module);
    expect(
        platform.supported && platform.windows && !platform.byval && platform.sret,
        "Windows byval rejection must not disable unrelated nonzero-position sret qualification");
    const auto admission = [&] {
      site.effective_abi = obf::make_proxy_abi_descriptor(*call);
      return obf::analyze_proxy_site(site, platform, obf::call_proxy_options{});
    };
    const auto byval_rejection = admission();
    expect(!byval_rejection.admitted && byval_rejection.code == "unsupported_win64_byval",
           "Windows C/Fast register-byval routes need a precise unsupported qualification result "
           "before emission");
    call->setTailCallKind(llvm::CallInst::TCK_MustTail);
    const auto tail_rejection = admission();
    expect(!tail_rejection.admitted && tail_rejection.code == "unsupported_win64_byval",
           "ABI-only original-musttail cannot bypass the same Windows byval backend qualification");

    // This is an intentionally different, valid ABI row, not an emitter
    // fallback: ordinary input pointer plus sret still at original index one.
    call->removeParamAttr(2, llvm::Attribute::ByVal);
    target->removeParamAttr(2, llvm::Attribute::ByVal);
    owner->removeParamAttr(2, llvm::Attribute::ByVal);
    const auto tail_sret = admission();
    expect(tail_sret.admitted && tail_sret.mode == obf::proxy_route_mode::abi_only,
           "qualified Windows nonzero-position sret with ordinary input pointer retains exact "
           "ABI-only admission");
    call->setTailCallKind(llvm::CallInst::TCK_None);
    const auto ordinary_sret = admission();
    expect(ordinary_sret.admitted && ordinary_sret.mode == obf::proxy_route_mode::stateful,
           "qualified Windows nonzero-position sret with ordinary input pointer retains stateful "
           "admission");
  }
}

void test_windows_vector_qualification_covers_both_routes() {
  for (auto convention : {llvm::CallingConv::C, llvm::CallingConv::Fast}) {
    for (unsigned shape : {0U, 1U, 2U}) {
      llvm::LLVMContext context;
      llvm::Module module("proxy.admission.windows.vector", context);
      module.setTargetTriple(llvm::Triple("x86_64-pc-windows-msvc"));
      module.setDataLayout(
          "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128");
      auto* scalar = llvm::Type::getInt32Ty(context);
      auto* vector = llvm::FixedVectorType::get(scalar, 4);
      llvm::Type* result_type = shape == 1 ? scalar : static_cast<llvm::Type*>(vector);
      llvm::Type* argument_type = shape == 2 ? scalar : static_cast<llvm::Type*>(vector);
      auto* signature = llvm::FunctionType::get(result_type, {argument_type}, false);
      auto* target =
          llvm::Function::Create(signature, llvm::GlobalValue::ExternalLinkage, "target", module);
      auto* owner =
          llvm::Function::Create(signature, llvm::GlobalValue::InternalLinkage, "owner", module);
      target->setCallingConv(convention);
      owner->setCallingConv(convention);
      llvm::IRBuilder<> builder(llvm::BasicBlock::Create(context, "entry", owner));
      auto* call = builder.CreateCall(target, {owner->getArg(0)});
      call->setCallingConv(convention);
      builder.CreateRet(call);
      obf::live_proxy_site site;
      site.owner_function = owner;
      site.replacement_call = call;
      site.decoded_target = target;
      site.expected_target = target;
      site.encoded_result = call;
      const auto admission = [&] {
        site.effective_abi = obf::make_proxy_abi_descriptor(*call);
        return obf::analyze_proxy_site(
            site, obf::proxy_platform_contract_for(module), obf::call_proxy_options{});
      };
      expect(!obf::proxy_platform_contract_for(module).vector,
             "Windows vector forwarding must remain unqualified after runtime failure, not merely "
             "backend compile success");
      for (auto tail : {llvm::CallInst::TCK_None, llvm::CallInst::TCK_MustTail}) {
        call->setTailCallKind(tail);
        const auto rejected = admission();
        expect(!rejected.admitted && rejected.code == "unsupported_win64_vector",
               "Windows C/Fast vector argument or return requires a precise rejection for stateful "
               "and ABI-only routes");
      }
      module.setTargetTriple(llvm::Triple("x86_64-unknown-linux-gnu"));
      module.setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
      expect(obf::proxy_platform_contract_for(module).vector && admission().admitted,
             "Windows vector qualification failure must not disable the qualified Linux C/Fast "
             "vector ABI-only row");
      call->setTailCallKind(llvm::CallInst::TCK_None);
      expect(admission().admitted,
             "Windows vector qualification failure must not disable the qualified Linux stateful "
             "vector row");
    }
  }
}
}  // namespace

int main() {
  test_native_owned_discovery_and_exclusions();
  test_missing_and_noncall_rauw_are_visible();
  test_replace_move_clone_and_rebuild();
  test_proven_dead_and_dead_owner();
  test_vm_explicit_target_token_and_encoded_result();
  test_vm_clone_and_result_bypass();
  test_vm_void_and_unencoded_result_roles();
  test_typed_abi_payload_and_original_tail();
  test_preserved_vm_obligation_without_selected_caller();
  test_admission_rejects_unqualified_hardening();
  test_admission_rejects_bundles_and_special_semantics();
  test_admission_typed_byval_alignment_and_unknown_abi();
  test_admission_exact_vm_thunk_does_not_disable_helper_exclusion();
  test_windows_byval_qualification_preserves_nonzero_sret();
  test_windows_vector_qualification_covers_both_routes();
  if (failures != 0) { return 1; }
  std::cout << "[ok] call_proxy_sites_tests passed\n";
  return 0;
}
