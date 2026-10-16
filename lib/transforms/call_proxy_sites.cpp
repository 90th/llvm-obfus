#include "obf/transforms/call_proxy_sites.h"

#include "obf/support/stable_hash.h"
#include "obf/support/runtime_abi_generated.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <limits>
#include <tuple>

namespace obf {
namespace {
constexpr llvm::StringLiteral site_marker = "obf.call.proxy.site";
constexpr llvm::StringLiteral role_marker = "obf.call.proxy.roles";
constexpr llvm::StringLiteral source_marker = "obf.call.proxy.source";

[[noreturn]] void fail(llvm::StringRef message) {
  llvm::report_fatal_error(llvm::Twine("call proxy registry: ") + message);
}

std::uint64_t nonzero(std::uint64_t value) { return value == 0 ? 1 : value; }
std::uint64_t module_identity(const llvm::Module& module) {
  return nonzero(
      stable_hash_string(module.getSourceFileName(),
                         stable_hash_string(module.getModuleIdentifier(),
                                            stable_hash_string(module.getTargetTriple().str()))));
}
std::uint64_t owner_identity(const llvm::Function& function) {
  return nonzero(stable_hash_string(function.getName(), module_identity(*function.getParent())));
}

llvm::Metadata* number(llvm::LLVMContext& context, std::uint64_t value) {
  return llvm::ConstantAsMetadata::get(
      llvm::ConstantInt::get(llvm::Type::getInt64Ty(context), value));
}
bool get_number(const llvm::MDNode* node, unsigned index, std::uint64_t& result) {
  if (node == nullptr || index >= node->getNumOperands()) { return false; }
  auto* metadata = llvm::dyn_cast_or_null<llvm::ConstantAsMetadata>(node->getOperand(index).get());
  auto* integer =
      metadata == nullptr ? nullptr : llvm::dyn_cast<llvm::ConstantInt>(metadata->getValue());
  if (integer == nullptr || integer->getBitWidth() != 64) { return false; }
  result = integer->getZExtValue();
  return true;
}
bool read_identity(const llvm::MDNode* node, source_site_identity& identity) {
  return get_number(node, 0, identity.module_id) && get_number(node, 1, identity.owner_id) &&
         get_number(node, 2, identity.site_id) && get_number(node, 3, identity.instance_id) &&
         identity.module_id != 0 && identity.owner_id != 0 && identity.site_id != 0 &&
         identity.instance_id != 0;
}
llvm::MDNode* identity_metadata(llvm::LLVMContext& context, const source_site_identity& identity) {
  return llvm::MDNode::get(context,
                           {number(context, identity.module_id),
                            number(context, identity.owner_id),
                            number(context, identity.site_id),
                            number(context, identity.instance_id)});
}
bool same_site(const llvm::MDNode* metadata, const source_site_identity& identity) {
  source_site_identity recorded;
  return read_identity(metadata, recorded) && recorded == identity;
}

void mark_role(llvm::Value* value, const live_proxy_site& site, llvm::StringRef role) {
  auto* instruction = llvm::dyn_cast_or_null<llvm::Instruction>(value);
  if (instruction == nullptr) { return; }
  llvm::SmallVector<llvm::Metadata*, 4> roles;
  if (auto* old = instruction->getMetadata(role_marker)) {
    for (const llvm::MDOperand& operand : old->operands()) {
      auto* item = llvm::dyn_cast_or_null<llvm::MDNode>(operand.get());
      if (item != nullptr && same_site(item, site.identity)) { continue; }
      roles.push_back(operand.get());
    }
  }
  auto& context = instruction->getContext();
  roles.push_back(llvm::MDNode::get(context,
                                    {number(context, site.identity.module_id),
                                     number(context, site.identity.owner_id),
                                     number(context, site.identity.site_id),
                                     number(context, site.identity.instance_id),
                                     number(context, site.binding.binding_id),
                                     llvm::MDString::get(context, role)}));
  instruction->setMetadata(role_marker, llvm::MDNode::get(context, roles));
}
bool has_role(const llvm::Value* value, const live_proxy_site& site, llvm::StringRef role) {
  const auto* instruction = llvm::dyn_cast_or_null<llvm::Instruction>(value);
  if (instruction == nullptr) { return llvm::isa_and_nonnull<llvm::Constant>(value); }
  const auto* metadata = instruction->getMetadata(role_marker);
  if (metadata == nullptr) { return false; }
  for (const llvm::MDOperand& operand : metadata->operands()) {
    const auto* item = llvm::dyn_cast_or_null<llvm::MDNode>(operand.get());
    std::uint64_t binding = 0;
    if (!same_site(item, site.identity) || !get_number(item, 4, binding) ||
        binding != site.binding.binding_id || item->getNumOperands() != 6) {
      continue;
    }
    const auto* name = llvm::dyn_cast_or_null<llvm::MDString>(item->getOperand(5).get());
    if (name != nullptr && name->getString() == role) { return true; }
  }
  return false;
}

bool depends_on(const llvm::Value* root, const llvm::Value* value) {
  if (root == nullptr || value == nullptr) { return false; }
  llvm::SmallVector<const llvm::Value*, 32> pending{root};
  llvm::SmallPtrSet<const llvm::Value*, 32> visited;
  while (!pending.empty()) {
    const auto* current = pending.pop_back_val();
    if (current == value) { return true; }
    if (!visited.insert(current).second) { continue; }
    // Follow instruction operands only; following a function's body or global
    // initializer could invent a dependency unrelated to this invocation.
    if (const auto* instruction = llvm::dyn_cast<llvm::Instruction>(current)) {
      for (const llvm::Use& operand : instruction->operands()) { pending.push_back(operand.get()); }
    }
  }
  return false;
}

std::vector<proxy_site_issue> validate_site(const live_proxy_site& site, bool metadata_required) {
  std::vector<proxy_site_issue> issues;
  const auto issue = [&](llvm::StringRef code, llvm::StringRef diagnostic) {
    issues.push_back({site.identity, code.str(), diagnostic.str()});
  };
  if (site.dead || site.consumed || !site.selected) { return issues; }
  auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(site.replacement_call);
  auto* owner = llvm::dyn_cast_or_null<llvm::Function>(site.owner_function);
  if (call == nullptr || call->getParent() == nullptr) {
    issue(
        "missing_live_call",
        "live call handle is null, detached, or followed a non-call RAUW without dead-site proof");
    return issues;
  }
  if (owner == nullptr || call->getFunction() != owner) {
    issue("wrong_live_owner", "call is not contained in its explicitly recorded live owner");
  }
  if (!proxy_abi_matches(*call, site.effective_abi)) {
    issue("changed_effective_abi",
          "effective call signature, qualified attributes, or subtarget identity changed");
  }
  if (call->getCalledOperand() != site.decoded_target) {
    issue("wrong_target_role", "call no longer consumes the registered target-pointer operand");
  }
  if (metadata_required) {
    auto* metadata = call->getMetadata(site_marker);
    std::uint64_t binding = 0;
    std::uint64_t token = 0;
    std::uint64_t abi = 0;
    std::uint64_t flags = 0;
    std::uint64_t binding_module = 0;
    std::uint64_t binding_owner = 0;
    std::uint64_t result_role = 0;
    std::uint64_t result_width = 0;
    const std::uint64_t expected_flags =
        (site.is_vm ? 1U : 0U) | (site.preserved_musttail ? 2U : 0U) | (site.required ? 4U : 0U) |
        (site.binding.no_cache ? 8U : 0U) | (site.preserved_unsupported ? 16U : 0U);
    if (!same_site(metadata, site.identity) || !get_number(metadata, 4, binding) ||
        binding != site.binding.binding_id || !get_number(metadata, 5, token) ||
        token != site.original_site_token || !get_number(metadata, 7, abi) ||
        abi != site.effective_abi.identity || !get_number(metadata, 6, flags) ||
        flags != expected_flags || !get_number(metadata, 9, binding_module) ||
        binding_module != site.binding.module_id || !get_number(metadata, 10, binding_owner) ||
        binding_owner != site.binding.owner_id || !get_number(metadata, 12, result_role) ||
        result_role != unsigned(site.return_contract.role) ||
        !get_number(metadata, 13, result_width) ||
        result_width != site.return_contract.integer_width) {
      issue("changed_site_identity",
            "site metadata no longer proves source, binding, token, and ABI identity");
    }
    if (metadata != nullptr && metadata->getNumOperands() == 16) {
      const auto* target =
          llvm::dyn_cast_or_null<llvm::ValueAsMetadata>(metadata->getOperand(8).get());
      const auto* tag = llvm::dyn_cast_or_null<llvm::MDString>(metadata->getOperand(11).get());
      const auto* key = llvm::dyn_cast_or_null<llvm::MDString>(metadata->getOperand(14).get());
      const auto* preservation =
          llvm::dyn_cast_or_null<llvm::MDString>(metadata->getOperand(15).get());
      if ((target == nullptr ? nullptr : target->getValue()) != site.expected_target ||
          tag == nullptr || tag->getString() != site.binding.symbol_tag || key == nullptr ||
          key->getString() != site.return_contract.key_global_name || preservation == nullptr ||
          preservation->getString() != site.preservation_reason) {
        issue("changed_binding_target",
              "site lost its exact target, binding tag, or return-key association");
      }
    } else {
      issue("missing_binding_roles",
            "site has no complete explicit binding and result-role metadata");
    }
    if (!has_role(site.decoded_target, site, "target")) {
      issue("missing_target_role", "target pointer lost its explicit operand role");
    }
    if (!has_role(call, site, "result")) {
      issue("missing_result_role",
            "call lost its explicit encoded, unchanged, or void result role");
    }
  }
  if (site.encoded_result != call) {
    issue("wrong_result_role", "encoded/unchanged/void result role is not the registered call");
  }
  if (!site.is_vm) {
    if (llvm::isa_and_nonnull<llvm::Constant>(site.decoded_target) &&
        site.expected_target != nullptr &&
        call->getCalledOperand()->stripPointerCasts() != site.expected_target) {
      issue("changed_native_target",
            "native symbolic callee no longer matches its admitted exact target");
    }
    return issues;
  }
  if (site.binding.binding_id == 0 || site.binding.module_id == 0 || site.binding.owner_id == 0 ||
      !llvm::isa_and_nonnull<llvm::Function>(site.expected_target)) {
    issue("missing_vm_binding",
          "VM site has no complete owned binding and expected target identity");
  }
  if (site.return_contract.binding_id != site.binding.binding_id ||
      site.return_contract.token != site.original_site_token) {
    issue("wrong_return_binding",
          "VM return contract does not belong to the recorded binding and token");
  }
  if (site.preserved_unsupported) {
    const bool expected_shape =
        (site.preservation_reason == "preserved_vm_invoke" && llvm::isa<llvm::InvokeInst>(call)) ||
        (site.preservation_reason == "preserved_vm_callbr" && llvm::isa<llvm::CallBrInst>(call)) ||
        (site.preservation_reason == "preserved_vm_operand_bundles" && call->hasOperandBundles()) ||
        (site.preservation_reason == "preserved_vm_abi_mismatch" &&
         llvm::isa<llvm::CallInst>(call)) ||
        (site.preservation_reason == "preserved_vm_target_resolution" &&
         llvm::isa<llvm::CallInst>(call) && !call->isMustTailCall());
    const auto expected_role = call->getType()->isVoidTy() ? vm_result_role::void_result
                                                           : vm_result_role::unchanged_result;
    if (!expected_shape || site.preserved_musttail || site.hidden_token_operand != nullptr ||
        site.return_decode_root != nullptr || site.original_site_token != 0 ||
        site.return_contract.role != expected_role ||
        call->getCalledOperand()->stripPointerCasts() != site.expected_target) {
      issue(
          "changed_preserved_boundary",
          "unsupported preserved VM site lost its exact original wrapper, ABI, or classification");
    }
    return issues;
  }
  if (site.preserved_musttail) {
    auto* instruction = llvm::dyn_cast<llvm::CallInst>(call);
    if (instruction == nullptr || !instruction->isMustTailCall() ||
        site.hidden_token_operand != nullptr || site.return_decode_root != nullptr ||
        call->getCalledOperand()->stripPointerCasts() != site.expected_target) {
      issue("changed_preserved_wrapper",
            "preserved original-musttail site must use the exact wrapper ABI without a token or "
            "decode");
    }
    return issues;
  }
  const auto* target_value = llvm::dyn_cast_or_null<llvm::Instruction>(site.decoded_target);
  if (target_value == nullptr || target_value->getFunction() != owner) {
    issue("lost_resolver_target",
          "fresh VM site must retain its live caller-local resolver-derived pointer SSA value");
  }
  if (const auto* token_value =
          llvm::dyn_cast_or_null<llvm::Instruction>(site.hidden_token_operand)) {
    if (token_value->getFunction() != owner) {
      issue("wrong_token_owner", "VM hidden token is not defined in the recorded live caller");
    }
  }
  if (call->arg_empty() || call->getArgOperand(call->arg_size() - 1) != site.hidden_token_operand ||
      site.hidden_token_operand == nullptr ||
      !static_cast<llvm::Value*>(site.hidden_token_operand)->getType()->isIntegerTy(64)) {
    issue("wrong_hidden_token",
          "VM call must consume the exact original i64 hidden-token operand in its original final "
          "parameter");
  }
  if (const auto* token = llvm::dyn_cast_or_null<llvm::ConstantInt>(site.hidden_token_operand)) {
    if (token->getBitWidth() != 64 || token->getZExtValue() != site.original_site_token) {
      issue("changed_constant_token",
            "constant VM hidden token is not bit-identical to the original site token");
    }
  }
  if (metadata_required && !has_role(site.hidden_token_operand, site, "token")) {
    issue("missing_token_role", "hidden token lost its explicit operand role");
  }
  if (site.return_contract.role == vm_result_role::void_result) {
    if (!call->getType()->isVoidTy() || site.return_decode_root != nullptr) {
      issue("wrong_void_result", "void VM return has a result decode or nonvoid effective type");
    }
  } else if (site.return_contract.role == vm_result_role::unchanged_result) {
    if (call->getType()->isVoidTy() || site.return_decode_root != nullptr) {
      issue("wrong_unchanged_result", "unencoded VM return must remain unchanged without a decode");
    }
  } else {
    auto* decode = llvm::dyn_cast_or_null<llvm::Instruction>(site.return_decode_root);
    auto* key = owner == nullptr || owner->getParent() == nullptr
                    ? nullptr
                    : owner->getParent()->getNamedGlobal(site.return_contract.key_global_name);
    if (!call->getType()->isIntegerTy(site.return_contract.integer_width) || decode == nullptr ||
        decode->getFunction() != owner || decode == call || decode->getType() != call->getType() ||
        !depends_on(decode, call) || !depends_on(decode, site.hidden_token_operand) ||
        key == nullptr || !depends_on(decode, key)) {
      issue("wrong_return_decode",
            "encoded integer result lost its original call/token/key-dependent caller decode");
    } else {
      if (metadata_required && !has_role(decode, site, "decode")) {
        issue("missing_decode_role", "caller return decode lost its explicit result role");
      }
      llvm::SmallPtrSet<const llvm::Value*, 32> decode_values;
      llvm::SmallVector<const llvm::Value*, 32> pending{decode};
      while (!pending.empty()) {
        const auto* value = pending.pop_back_val();
        if (!decode_values.insert(value).second || value == call) { continue; }
        if (const auto* instruction = llvm::dyn_cast<llvm::Instruction>(value)) {
          for (const llvm::Use& operand : instruction->operands()) {
            pending.push_back(operand.get());
          }
        }
      }
      for (const llvm::User* user : call->users()) {
        if (!decode_values.contains(user)) {
          issue("bypassed_return_decode",
                "encoded VM result has a use outside its one registered caller-decode expression");
          break;
        }
      }
    }
  }
  return issues;
}

void require_valid(const live_proxy_site& site) {
  const auto issues = validate_site(site, false);
  if (!issues.empty()) { fail(issues.front().diagnostic); }
}

bool source_less(const source_site_identity& left, const source_site_identity& right) {
  return std::tie(left.module_id, left.owner_id, left.site_id, left.instance_id) <
         std::tie(right.module_id, right.owner_id, right.site_id, right.instance_id);
}
}  // namespace

proxy_abi_descriptor make_proxy_abi_descriptor(const llvm::CallBase& call) {
  proxy_abi_descriptor descriptor;
  descriptor.function_type = call.getFunctionType();
  descriptor.return_type = call.getType();
  for (auto* type : call.getFunctionType()->params()) { descriptor.argument_types.push_back(type); }
  descriptor.calling_convention = call.getCallingConv();
  descriptor.pointer_address_space = call.getCalledOperand()->getType()->getPointerAddressSpace();
  descriptor.attributes = call.getAttributes();
  const auto* owner = call.getFunction();
  const auto* module = owner == nullptr ? nullptr : owner->getParent();
  const auto text_attribute = [&](llvm::StringRef name) {
    return owner == nullptr || !owner->hasFnAttribute(name)
               ? std::string{}
               : owner->getFnAttribute(name).getValueAsString().str();
  };
  descriptor.target_cpu = text_attribute("target-cpu");
  descriptor.target_features = text_attribute("target-features");
  descriptor.tune_cpu = text_attribute("tune-cpu");
  descriptor.frame_pointer = text_attribute("frame-pointer");
  descriptor.no_red_zone = owner != nullptr && owner->hasFnAttribute(llvm::Attribute::NoRedZone)
                               ? "noredzone"
                               : text_attribute("no-red-zone");
  descriptor.target_identity = module == nullptr ? std::string{} : module->getTargetTriple().str();
  std::string shape;
  llvm::raw_string_ostream stream(shape);
  descriptor.function_type->print(stream);
  stream << ':' << descriptor.calling_convention << ':' << descriptor.pointer_address_space << ':'
         << descriptor.target_identity << ':' << descriptor.target_cpu << ':'
         << descriptor.target_features << ':' << descriptor.tune_cpu << ':'
         << descriptor.frame_pointer << ':' << descriptor.no_red_zone;
  for (unsigned index = 0; index <= call.arg_size(); ++index) {
    for (const auto attribute : call.getAttributes().getAttributes(index)) {
      proxy_abi_attribute qualified;
      qualified.index = index;
      qualified.kind = attribute.isStringAttribute()
                           ? attribute.getKindAsString().str()
                           : llvm::Attribute::getNameFromAttrKind(attribute.getKindAsEnum()).str();
      qualified.value = attribute.getAsString();
      if (attribute.isTypeAttribute()) {
        qualified.payload_type = attribute.getValueAsType();
        if (module != nullptr && qualified.payload_type->isSized()) {
          const auto size = module->getDataLayout().getTypeAllocSize(qualified.payload_type);
          qualified.allocation_size =
              size.isScalable() ? std::numeric_limits<std::uint64_t>::max() : size.getFixedValue();
          qualified.abi_alignment =
              module->getDataLayout().getABITypeAlign(qualified.payload_type).value();
        }
      }
      if (index > 0) {
        if (const auto alignment = call.getParamAlign(index - 1)) {
          qualified.explicit_alignment = alignment->value();
        }
      }
      stream << ':' << index << ':' << qualified.value << ':' << qualified.allocation_size << ':'
             << qualified.abi_alignment << ':' << qualified.explicit_alignment;
      descriptor.qualified_attributes.push_back(std::move(qualified));
    }
  }
  descriptor.identity = nonzero(stable_hash_string(stream.str()));
  return descriptor;
}

bool proxy_abi_matches(const llvm::CallBase& call, const proxy_abi_descriptor& expected) {
  const auto actual = make_proxy_abi_descriptor(call);
  return actual.function_type == expected.function_type &&
         actual.return_type == expected.return_type &&
         actual.argument_types == expected.argument_types &&
         actual.calling_convention == expected.calling_convention &&
         actual.pointer_address_space == expected.pointer_address_space &&
         actual.qualified_attributes == expected.qualified_attributes &&
         actual.target_cpu == expected.target_cpu &&
         actual.target_features == expected.target_features &&
         actual.tune_cpu == expected.tune_cpu && actual.frame_pointer == expected.frame_pointer &&
         actual.no_red_zone == expected.no_red_zone &&
         actual.target_identity == expected.target_identity && actual.identity == expected.identity;
}

bool is_call_proxy_infrastructure(const llvm::Function& function) {
  const auto name = function.getName();
  if (function.isIntrinsic() || name.starts_with(OBF_RT_ABI_PREFIX_STR) ||
      name.starts_with("__obf_") || name.starts_with("_obf_") || name.contains("ObfEntropy") ||
      name.contains("ObfBlake") || function.hasFnAttribute("obf.call.proxy.hop") ||
      function.hasFnAttribute("obf.call.proxy.bridge") ||
      function.hasFnAttribute("obf.lto.proxy.role") ||
      function.getMetadata("obf.string_copy.helper") != nullptr) {
    return true;
  }
  // Accessors need not have generated names. The source declaration is the
  // authoritative helper/accessor association, including private auth paths.
  if (const auto* module = function.getParent()) {
    for (const auto& global : module->globals()) {
      const auto* metadata = global.getMetadata("obf.string_copy.source");
      if (metadata == nullptr || metadata->getNumOperands() < 2) { continue; }
      for (unsigned index = 0; index < 2; ++index) {
        const auto* value =
            llvm::dyn_cast_or_null<llvm::ValueAsMetadata>(metadata->getOperand(index).get());
        if (value != nullptr && value->getValue() == &function) { return true; }
      }
    }
  }
  return false;
}

void live_proxy_site_registry::snapshot_source_sites(llvm::Module& module) {
  if (source_snapshot_taken_) {
    if (source_module_ != &module) { fail("one live-site registry cannot span multiple modules"); }
    return;
  }
  source_snapshot_taken_ = true;
  source_module_ = &module;
  for (auto& function : module) {
    for (auto& block : function) {
      for (auto& instruction : block) {
        if (auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) { source_identity(*call); }
      }
    }
  }
}

void live_proxy_site_registry::register_selected_owner(llvm::Function& function,
                                                       std::uint64_t seed,
                                                       bool required) {
  for (auto& owner : owners_) {
    if (owner.function == &function) {
      if (owner.decision_seed != seed || owner.required != required) {
        fail("selected owner policy changed during registration");
      }
      return;
    }
  }
  if (function.getParent() == nullptr) { fail("cannot select a detached owner"); }
  owners_.push_back({&function,
                     module_identity(*function.getParent()),
                     owner_identity(function),
                     seed,
                     required});
  snapshot_source_sites(*function.getParent());
}

bool live_proxy_site_registry::owner_selected(const llvm::Function& function) const {
  return std::any_of(owners_.begin(), owners_.end(), [&](const auto& owner) {
    return owner.function == &function;
  });
}

bool live_proxy_site_registry::owner_required(const llvm::Function& function) const {
  for (const auto& owner : owners_) {
    if (owner.function == &function) { return owner.required; }
  }
  return false;
}

source_site_identity live_proxy_site_registry::source_identity(llvm::CallBase& call) {
  source_site_identity identity;
  if (read_identity(call.getMetadata(source_marker), identity)) { return identity; }
  auto* owner = call.getFunction();
  if (owner == nullptr || owner->getParent() == nullptr) {
    fail("cannot identify a detached call");
  }
  identity.module_id = module_identity(*owner->getParent());
  identity.owner_id = owner_identity(*owner);
  std::uint64_t ordinal = 0;
  bool found = false;
  for (auto& block : *owner) {
    for (auto& instruction : block) {
      if (llvm::isa<llvm::CallBase>(instruction)) { ++ordinal; }
      if (&instruction == &call) {
        found = true;
        break;
      }
    }
    if (found) { break; }
  }
  identity.site_id = nonzero(mix_seed(identity.owner_id, ordinal));
  identity.instance_id = nonzero(mix_seed(identity.site_id, 0x696e7374616e6365ULL));
  call.setMetadata(source_marker, identity_metadata(call.getContext(), identity));
  return identity;
}

live_proxy_site& live_proxy_site_registry::lookup(const source_site_identity& identity) {
  for (auto& site : sites_) {
    if (site.identity == identity) { return site; }
  }
  fail("unknown live-site identity");
}
const live_proxy_site&
live_proxy_site_registry::lookup(const source_site_identity& identity) const {
  for (const auto& site : sites_) {
    if (site.identity == identity) { return site; }
  }
  fail("unknown live-site identity");
}

void live_proxy_site_registry::annotate(live_proxy_site& site) {
  auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(site.replacement_call);
  if (call == nullptr) { fail("cannot annotate a missing call"); }
  auto& context = call->getContext();
  std::uint64_t flags = (site.is_vm ? 1U : 0U) | (site.preserved_musttail ? 2U : 0U) |
                        (site.required ? 4U : 0U) | (site.binding.no_cache ? 8U : 0U) |
                        (site.preserved_unsupported ? 16U : 0U);
  llvm::Metadata* target = llvm::MDString::get(context, "unproved");
  if (auto* value = llvm::dyn_cast_or_null<llvm::Function>(site.expected_target)) {
    target = llvm::ValueAsMetadata::get(value);
  }
  call->setMetadata(source_marker, identity_metadata(context, site.identity));
  call->setMetadata(
      site_marker,
      llvm::MDNode::get(context,
                        {number(context, site.identity.module_id),
                         number(context, site.identity.owner_id),
                         number(context, site.identity.site_id),
                         number(context, site.identity.instance_id),
                         number(context, site.binding.binding_id),
                         number(context, site.original_site_token),
                         number(context, flags),
                         number(context, site.effective_abi.identity),
                         target,
                         number(context, site.binding.module_id),
                         number(context, site.binding.owner_id),
                         llvm::MDString::get(context, site.binding.symbol_tag),
                         number(context, unsigned(site.return_contract.role)),
                         number(context, site.return_contract.integer_width),
                         llvm::MDString::get(context, site.return_contract.key_global_name),
                         llvm::MDString::get(context, site.preservation_reason)}));
  mark_role(site.decoded_target, site, "target");
  if (site.hidden_token_operand != nullptr) { mark_role(site.hidden_token_operand, site, "token"); }
  if (site.return_decode_root != nullptr) { mark_role(site.return_decode_root, site, "decode"); }
  mark_role(call, site, "result");
}

void live_proxy_site_registry::register_rewrite(llvm::CallBase& old_call, vm_rewritten_site site) {
  site.identity = source_identity(old_call);
  site.source_owner_function = old_call.getFunction();
  for (const auto& owner : owners_) {
    if (owner.module_id == site.identity.module_id && owner.owner_id == site.identity.owner_id) {
      site.source_owner_function = owner.function;
      site.required |= owner.required;
      break;
    }
  }
  auto* replacement = llvm::dyn_cast_or_null<llvm::CallBase>(site.replacement_call);
  if (replacement == nullptr) { fail("rewrite does not provide a live replacement call"); }
  site.owner_function = replacement->getFunction();
  site.is_vm = true;
  if (site.preserved_musttail || site.preserved_unsupported) {
    fail("rewritten VM site cannot be a preserved original boundary");
  }
  require_valid(site);
  for (auto& existing : sites_) {
    if (existing.identity == site.identity) {
      if (existing.replacement_call != &old_call || existing.is_vm) {
        fail("duplicate source/instance identity");
      }
      existing = std::move(site);
      annotate(existing);
      return;
    }
  }
  sites_.push_back(std::move(site));
  annotate(sites_.back());
}

void live_proxy_site_registry::register_preserved_site(llvm::CallBase& call, live_proxy_site site) {
  site.identity = source_identity(call);
  site.source_owner_function = call.getFunction();
  for (const auto& owner : owners_) {
    if (owner.module_id == site.identity.module_id && owner.owner_id == site.identity.owner_id) {
      site.source_owner_function = owner.function;
      site.required |= owner.required;
      break;
    }
  }
  site.owner_function = call.getFunction();
  site.replacement_call = &call;
  site.encoded_result = &call;
  site.decoded_target = call.getCalledOperand();
  site.is_vm = true;
  if (!site.preserved_musttail && !site.preserved_unsupported) {
    fail("preserved VM site requires an exact-tail route or explicit unsupported classification");
  }
  require_valid(site);
  for (const auto& existing : sites_) {
    if (existing.identity == site.identity) {
      fail("duplicate preserved source/instance identity");
    }
  }
  sites_.push_back(std::move(site));
  annotate(sites_.back());
}

void live_proxy_site_registry::register_preserved_musttail(llvm::CallBase& call,
                                                           live_proxy_site site) {
  site.preserved_musttail = true;
  register_preserved_site(call, std::move(site));
}

void live_proxy_site_registry::discover_native_sites(llvm::Module& module) {
  for (auto& function : module) {
    if (is_call_proxy_infrastructure(function)) { continue; }
    for (auto& block : function) {
      for (auto& instruction : block) {
        auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call == nullptr || call->getMetadata(site_marker) != nullptr) { continue; }
        auto* target =
            llvm::dyn_cast<llvm::Function>(call->getCalledOperand()->stripPointerCasts());
        if (target != nullptr && is_call_proxy_infrastructure(*target)) { continue; }
        source_site_identity identity;
        const bool marked = read_identity(call->getMetadata(source_marker), identity);
        if (!marked) { continue; }
        const selected_owner* selected = nullptr;
        for (const auto& owner : owners_) {
          if (owner.module_id == identity.module_id && owner.owner_id == identity.owner_id) {
            selected = &owner;
            break;
          }
        }
        if (selected == nullptr) { continue; }
        live_proxy_site site;
        site.identity = identity;
        site.source_owner_function = selected->function;
        site.owner_function = &function;
        site.replacement_call = call;
        site.decoded_target = call->getCalledOperand();
        site.encoded_result = call;
        site.expected_target = target;
        site.decision_seed = selected->decision_seed;
        site.required = selected->required;
        site.effective_abi = make_proxy_abi_descriptor(*call);
        site.return_contract.role = call->getType()->isVoidTy() ? vm_result_role::void_result
                                                                : vm_result_role::unchanged_result;
        auto duplicate = std::find_if(sites_.begin(), sites_.end(), [&](const auto& entry) {
          return entry.identity == identity;
        });
        if (duplicate != sites_.end()) {
          clone_site(identity, std::move(site));
        } else {
          sites_.push_back(std::move(site));
          annotate(sites_.back());
        }
      }
    }
  }
}

void live_proxy_site_registry::replace_site(const source_site_identity& identity,
                                            live_proxy_site replacement) {
  auto& old = lookup(identity);
  if (old.dead || old.consumed || replacement.identity != identity ||
      replacement.binding != old.binding ||
      replacement.original_site_token != old.original_site_token ||
      replacement.return_contract != old.return_contract || replacement.is_vm != old.is_vm ||
      replacement.preserved_musttail != old.preserved_musttail ||
      replacement.preserved_unsupported != old.preserved_unsupported ||
      replacement.preservation_reason != old.preservation_reason ||
      replacement.expected_target != old.expected_target ||
      replacement.source_owner_function != old.source_owner_function ||
      replacement.decision_seed != old.decision_seed || replacement.required != old.required ||
      replacement.selected != old.selected || replacement.effective_abi != old.effective_abi) {
    fail("replacement changes a source, policy, binding, target, ABI, or return-contract identity");
  }
  require_valid(replacement);
  if (!has_role(replacement.decoded_target, old, "target") ||
      (replacement.hidden_token_operand != nullptr &&
       !has_role(replacement.hidden_token_operand, old, "token")) ||
      (replacement.return_decode_root != nullptr &&
       !has_role(replacement.return_decode_root, old, "decode"))) {
    fail("replacement lost the explicitly preserved target/token/decode operand roles");
  }
  old = std::move(replacement);
  annotate(old);
}

void live_proxy_site_registry::move_site(const source_site_identity& identity,
                                         llvm::Function& owner) {
  auto replacement = lookup(identity);
  replacement.owner_function = &owner;
  replace_site(identity, std::move(replacement));
}

source_site_identity live_proxy_site_registry::clone_site(const source_site_identity& identity,
                                                          live_proxy_site clone) {
  const auto original = lookup(identity);
  if (original.dead || original.consumed) {
    fail("cannot clone a discharged protection obligation");
  }
  auto clone_identity = identity;
  auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(clone.replacement_call);
  if (call == nullptr || call->getFunction() == nullptr) {
    fail("clone does not provide a live call");
  }
  std::uint64_t ordinal = 0;
  bool found_call = false;
  for (const auto& block : *call->getFunction()) {
    for (const auto& instruction : block) {
      if (&instruction == call) {
        found_call = true;
        break;
      }
      ++ordinal;
    }
    if (found_call) { break; }
  }
  std::uint64_t salt = mix_seed(owner_identity(*call->getFunction()), ordinal);
  do {
    clone_identity.instance_id = nonzero(mix_seed(identity.instance_id, ++salt));
  } while (std::any_of(sites_.begin(), sites_.end(), [&](const auto& entry) {
    return entry.identity == clone_identity;
  }));
  if (clone.identity != identity || clone.source_owner_function != original.source_owner_function) {
    fail("clone changes its original source ownership");
  }
  if (clone.binding != original.binding || clone.return_contract != original.return_contract ||
      clone.original_site_token != original.original_site_token ||
      clone.expected_target != original.expected_target ||
      clone.effective_abi != original.effective_abi || clone.is_vm != original.is_vm ||
      clone.preserved_musttail != original.preserved_musttail ||
      clone.required != original.required ||
      clone.preserved_unsupported != original.preserved_unsupported ||
      clone.preservation_reason != original.preservation_reason ||
      clone.selected != original.selected || clone.decision_seed != original.decision_seed) {
    fail("clone lacks a complete matching source, policy, binding, ABI, and result association");
  }
  require_valid(clone);
  clone.identity = clone_identity;
  clone.owner_function = call->getFunction();
  sites_.push_back(std::move(clone));
  annotate(sites_.back());
  return clone_identity;
}

void live_proxy_site_registry::replace_value(const source_site_identity& identity,
                                             proxy_value_role role,
                                             llvm::Value& value) {
  auto replacement = lookup(identity);
  auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(replacement.replacement_call);
  if (call == nullptr) { fail("value replacement does not have a live call"); }
  switch (role) {
    case proxy_value_role::decoded_target:
      replacement.decoded_target = &value;
      break;
    case proxy_value_role::hidden_token:
      replacement.hidden_token_operand = &value;
      break;
    case proxy_value_role::encoded_result:
      replacement.encoded_result = &value;
      break;
    case proxy_value_role::return_decode:
      replacement.return_decode_root = &value;
      break;
  }
  replace_site(identity, std::move(replacement));
}

proxy_dead_site_proof
live_proxy_site_registry::prove_dead_site(const source_site_identity& identity) const {
  const auto& site = lookup(identity);
  auto* call = llvm::dyn_cast_or_null<llvm::CallBase>(site.replacement_call);
  // A return value being unused is not enough: a call can have side effects.
  // The deleting transform must prove the entire containing block unreachable.
  if (call == nullptr || call->getParent() == nullptr || call->getFunction() == nullptr ||
      !call->use_empty() || call->getParent() == &call->getFunction()->getEntryBlock()) {
    fail("dead-site proof requires an unused call in an unreachable non-entry block");
  }
  llvm::SmallPtrSet<const llvm::BasicBlock*, 32> reachable;
  llvm::SmallVector<const llvm::BasicBlock*, 16> pending{&call->getFunction()->getEntryBlock()};
  while (!pending.empty()) {
    const auto* block = pending.pop_back_val();
    if (!reachable.insert(block).second) { continue; }
    if (const auto* terminator = block->getTerminator()) {
      for (unsigned index = 0; index < terminator->getNumSuccessors(); ++index) {
        pending.push_back(terminator->getSuccessor(index));
      }
    }
  }
  if (reachable.contains(call->getParent())) {
    fail("call's live protection obligation is not proved dead");
  }
  proxy_dead_site_proof proof;
  proof.identity = identity;
  proof.witness = nonzero(mix_seed(identity.instance_id, 0x6465616473697465ULL));
  proof.issuer = this;
  proof.original_call = call;
  return proof;
}

void live_proxy_site_registry::erase_dead_site(const source_site_identity& identity,
                                               const proxy_dead_site_proof& proof) {
  auto& site = lookup(identity);
  const bool unreachable =
      proof.witness == nonzero(mix_seed(identity.instance_id, 0x6465616473697465ULL));
  if (proof.issuer != this || proof.identity != identity || !unreachable) {
    fail("dead-site deletion lacks a matching registry-issued dead-obligation witness");
  }
  if (proof.original_call != nullptr) {
    fail("dead-site removal must follow actual deletion of the proved original call");
  }
  site.dead = true;
}

std::vector<proxy_site_issue> live_proxy_site_registry::validate() const {
  std::vector<proxy_site_issue> issues;
  for (const auto& site : sites_) {
    auto found = validate_site(site, true);
    issues.insert(issues.end(), found.begin(), found.end());
  }
  return issues;
}

std::vector<proxy_site_issue> live_proxy_site_registry::rebuild(llvm::Module& module) {
  // Snapshot: appending clones must not invalidate references into sites_.
  const auto originals = sites_;
  std::vector<proxy_site_issue> issues;
  for (const auto& original : originals) {
    if (original.dead || original.consumed || !original.selected) { continue; }
    if (original.replacement_call != nullptr &&
        !llvm::isa<llvm::CallBase>(static_cast<llvm::Value*>(original.replacement_call))) {
      issues.push_back(
          {original.identity,
           "noncall_rauw",
           "tracking handle followed a non-call result without an explicit lifecycle update"});
      continue;
    }
    llvm::SmallVector<llvm::CallBase*, 4> calls;
    for (auto& function : module) {
      for (auto& block : function) {
        for (auto& instruction : block) {
          auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
          if (call != nullptr && same_site(call->getMetadata(site_marker), original.identity)) {
            calls.push_back(call);
          }
        }
      }
    }
    if (calls.empty()) {
      // Whole-owner deletion is a concrete dead-obligation proof; an erased
      // call in a still-live owner is deliberately not treated the same way.
      if (original.source_owner_function == nullptr && original.owner_function == nullptr &&
          original.replacement_call == nullptr) {
        lookup(original.identity).dead = true;
      } else {
        issues.push_back(
            {original.identity,
             "unproved_site_removal",
             "no explicit live site remains and there is no dead-owner/dead-site proof"});
      }
      continue;
    }
    // Preserve the old live instance where possible; order remaining clones by
    // stable module/function/block/instruction traversal, never pointer address.
    auto old =
        std::find(calls.begin(), calls.end(), static_cast<llvm::Value*>(original.replacement_call));
    if (old != calls.end()) { std::iter_swap(calls.begin(), old); }
    bool first = true;
    for (auto* call : calls) {
      live_proxy_site rebuilt = original;
      rebuilt.owner_function = call->getFunction();
      rebuilt.replacement_call = call;
      rebuilt.encoded_result = call;
      rebuilt.decoded_target = call->getCalledOperand();
      if (original.is_vm && !original.preserved_musttail && !original.preserved_unsupported) {
        if (!call->arg_empty()) {
          rebuilt.hidden_token_operand = call->getArgOperand(call->arg_size() - 1);
        }
        if (original.return_contract.role == vm_result_role::encoded_integer) {
          llvm::Instruction* decode = nullptr;
          unsigned count = 0;
          for (auto& block : *call->getFunction()) {
            for (auto& instruction : block) {
              if (has_role(&instruction, original, "decode") && depends_on(&instruction, call)) {
                decode = &instruction;
                ++count;
              }
            }
          }
          rebuilt.return_decode_root = decode;
          if (count != 1) {
            issues.push_back({original.identity,
                              "ambiguous_return_decode",
                              "live instance does not have exactly one explicit call-dependent "
                              "return-decode root"});
            continue;
          }
        }
      }
      const auto found = validate_site(rebuilt, true);
      if (!found.empty()) {
        issues.insert(issues.end(), found.begin(), found.end());
        continue;
      }
      // Rebuild is only allowed to transfer semantic roles that were explicitly
      // retained. In particular token RAUW without role metadata is rejected.
      if (first) {
        replace_site(original.identity, std::move(rebuilt));
        first = false;
      } else {
        clone_site(original.identity, std::move(rebuilt));
      }
    }
  }
  std::sort(sites_.begin(), sites_.end(), [](const auto& left, const auto& right) {
    return source_less(left.identity, right.identity);
  });
  const auto found = validate();
  issues.insert(issues.end(), found.begin(), found.end());
  return issues;
}

}  // namespace obf
