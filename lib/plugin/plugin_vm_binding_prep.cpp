#include "obf/plugin/internal/plugin_vm_binding_prep.h"

#include "obf/plugin/obfuscator_plugin_internal.h"
#include "obf/frontend/config.h"

#include "obf/support/generated_names.h"
#include "obf/support/mba_config_builder.h"
#include "obf/transforms/mba.h"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <string>

namespace obf {

namespace {

bool is_vm_abi_safe_return_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }

  switch (attribute.getKindAsEnum()) {
    case llvm::Attribute::SExt:
    case llvm::Attribute::ZExt:
      return true;
    default:
      return false;
  }
}

bool is_vm_abi_safe_parameter_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }

  switch (attribute.getKindAsEnum()) {
    case llvm::Attribute::SExt:
    case llvm::Attribute::ZExt:
      return true;
    default:
      return false;
  }
}

// Parameter/return attributes that change how an argument is passed or
// returned. Cloning with an appended hidden token or forwarding through an
// indirect thunk cannot preserve these, so a target carrying any of them is
// rejected at the VM boundary rather than silently stripped. `inalloca` is the
// concretely verifier-invalid case (it must remain the last parameter); the
// rest are ABI-unsafe to forward.
bool is_abi_affecting_boundary_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }

  switch (attribute.getKindAsEnum()) {
    case llvm::Attribute::ByRef:
    case llvm::Attribute::ByVal:
    case llvm::Attribute::ElementType:
    case llvm::Attribute::InAlloca:
    case llvm::Attribute::InReg:
    case llvm::Attribute::Nest:
    case llvm::Attribute::Preallocated:
    case llvm::Attribute::StructRet:
    case llvm::Attribute::SwiftAsync:
    case llvm::Attribute::SwiftError:
    case llvm::Attribute::SwiftSelf:
      return true;
    default:
      return false;
  }
}

bool attribute_set_has_abi_affecting(llvm::AttributeSet attributes) {
  for (llvm::Attribute attribute : attributes) {
    if (is_abi_affecting_boundary_attribute(attribute)) { return true; }
  }
  return false;
}

bool attribute_set_abi_relevant_differs(llvm::AttributeSet lhs, llvm::AttributeSet rhs) {
  const auto is_abi_relevant = [](llvm::Attribute attribute) {
    if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }
    switch (attribute.getKindAsEnum()) {
      case llvm::Attribute::SExt:
      case llvm::Attribute::ZExt:
        return true;
      default:
        return is_abi_affecting_boundary_attribute(attribute);
    }
  };
  for (llvm::Attribute attribute : lhs) {
    if (is_abi_relevant(attribute) && !rhs.hasAttribute(attribute.getKindAsEnum())) { return true; }
  }
  for (llvm::Attribute attribute : rhs) {
    if (is_abi_relevant(attribute) && !lhs.hasAttribute(attribute.getKindAsEnum())) { return true; }
  }
  return false;
}

// A rewritable ordinary call must share the callee's ABI contract. Any
// disagreement on sign/zero extension or an ABI-affecting attribute at a
// matching index is preserved as an ABI mismatch rather than rewritten.
bool callsite_abi_mismatches_target(const llvm::CallBase& call, const llvm::Function& target) {
  const llvm::AttributeList call_attributes = call.getAttributes();
  const llvm::AttributeList target_attributes = target.getAttributes();
  if (attribute_set_abi_relevant_differs(call_attributes.getRetAttrs(),
                                         target_attributes.getRetAttrs())) {
    return true;
  }
  for (unsigned index = 0; index < target.arg_size(); ++index) {
    if (attribute_set_abi_relevant_differs(call_attributes.getParamAttrs(index),
                                           target_attributes.getParamAttrs(index))) {
      return true;
    }
  }
  return false;
}

llvm::StringRef vm_incoming_site_kind_name(vm_incoming_site_kind kind) {
  switch (kind) {
    case vm_incoming_site_kind::ordinary_call:
      return "ordinary call";
    case vm_incoming_site_kind::invoke:
      return "invoke";
    case vm_incoming_site_kind::callbr:
      return "callbr";
    case vm_incoming_site_kind::musttail:
      return "musttail call";
    case vm_incoming_site_kind::operand_bundles:
      return "operand-bundle call";
    case vm_incoming_site_kind::abi_mismatch:
      return "ABI-incompatible call";
  }
  return "call";
}

// Strict VM boundary: high-security profiles or the strong_vm level must fail
// closed rather than silently leave a call path unvirtualized.
bool requires_strict_vm_boundary(const obfuscation_config& config, protection_level level) {
  if (level == protection_level::strong_vm) { return true; }
  return config.profile == config_profile::fortress || config.profile == config_profile::lab;
}

}  // namespace

llvm::AttributeList build_vm_abi_attribute_list(const llvm::Function& function) {
  llvm::LLVMContext& context = function.getContext();
  const llvm::AttributeList original = function.getAttributes();
  llvm::AttributeList sanitized;

  for (llvm::Attribute attribute : original.getRetAttrs()) {
    if (is_vm_abi_safe_return_attribute(attribute)) {
      sanitized = sanitized.addRetAttribute(context, attribute);
    }
  }

  for (const llvm::Argument& argument : function.args()) {
    const unsigned argument_index = argument.getArgNo();
    for (llvm::Attribute attribute : original.getParamAttrs(argument_index)) {
      if (is_vm_abi_safe_parameter_attribute(attribute)) {
        sanitized = sanitized.addAttributeAtIndex(
            context, llvm::AttributeList::FirstArgIndex + argument_index, attribute);
      }
    }
  }

  return sanitized;
}

vm_boundary_analysis analyze_vm_boundary(const llvm::Function& target,
                                         llvm::ArrayRef<llvm::CallBase*> sites) {
  vm_boundary_analysis analysis;

  if (target.isVarArg()) {
    analysis.target_reason = "variadic functions are unsupported at the VM boundary";
    return analysis;
  }

  const llvm::AttributeList attributes = target.getAttributes();
  if (attribute_set_has_abi_affecting(attributes.getRetAttrs())) {
    analysis.target_reason = "return carries an ABI-affecting attribute unsupported at the VM boundary";
    return analysis;
  }
  for (const llvm::Argument& argument : target.args()) {
    if (attribute_set_has_abi_affecting(attributes.getParamAttrs(argument.getArgNo()))) {
      analysis.target_reason = "a parameter carries an ABI-affecting attribute unsupported at the VM boundary";
      return analysis;
    }
  }

  analysis.target_supported = true;
  analysis.sites.reserve(sites.size());
  for (llvm::CallBase* call : sites) {
    vm_boundary_site site;
    site.call = call;
    if (call == nullptr) {
      site.kind = vm_incoming_site_kind::abi_mismatch;
      site.rewritable = false;
    } else if (llvm::isa<llvm::InvokeInst>(call)) {
      site.kind = vm_incoming_site_kind::invoke;
      site.rewritable = false;
    } else if (llvm::isa<llvm::CallBrInst>(call)) {
      site.kind = vm_incoming_site_kind::callbr;
      site.rewritable = false;
    } else if (call->getNumOperandBundles() != 0) {
      site.kind = vm_incoming_site_kind::operand_bundles;
      site.rewritable = false;
    } else if (call->isMustTailCall()) {
      site.kind = vm_incoming_site_kind::musttail;
      site.rewritable = false;
    } else if (callsite_abi_mismatches_target(*call, target)) {
      site.kind = vm_incoming_site_kind::abi_mismatch;
      site.rewritable = false;
    } else {
      site.kind = vm_incoming_site_kind::ordinary_call;
      site.rewritable = true;
    }
    if (!site.rewritable) { analysis.has_preserved_site = true; }
    analysis.sites.push_back(site);
  }
  return analysis;
}

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_vm_hidden_token(std::uint64_t decision_seed,
                                     llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal) {
  std::uint64_t seed = stable_hash_string(callee_name);
  seed = mix_vm_handshake_seed(seed, stable_hash_string(caller_name));
  seed = mix_vm_handshake_seed(seed, ordinal + 1);
  if (decision_seed != 0) { seed = mix_vm_handshake_seed(seed, decision_seed); }
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

std::uint64_t derive_vm_wrapper_token(std::uint64_t decision_seed, llvm::StringRef function_name) {
  return derive_vm_hidden_token(decision_seed, function_name, function_name, 0x51f15eedULL);
}

std::string make_debug_vm_name(llvm::StringRef prefix, llvm::StringRef source_name) {
  return (prefix + source_name).str();
}

std::string make_vm_generated_symbol_name(llvm::Module& module,
                                          bool preserve_generated_names,
                                          llvm::StringRef role,
                                          llvm::StringRef source_name,
                                          std::uint64_t seed,
                                          llvm::StringRef debug_prefix) {
  if (preserve_generated_names) { return make_debug_vm_name(debug_prefix, source_name); }

  return make_unique_obf_symbol_name(module, role, source_name, seed);
}

std::string make_vm_symbol_tag(llvm::Module& module,
                               bool preserve_generated_names,
                               llvm::StringRef source_name,
                               std::uint64_t seed) {
  if (preserve_generated_names) { return source_name.str(); }

  const std::uint64_t tag_seed = mix_generated_name_seed(seed, 0x71a6c0de2f00dULL);
  const std::string base = make_obf_symbol_name("i", source_name, tag_seed);
  for (std::uint64_t suffix = 0;; ++suffix) {
    const std::string candidate = suffix == 0 ? base : base + "_" + std::to_string(suffix);
    if (module.getNamedValue(std::string("__obf_vm_bc_") + candidate) == nullptr &&
        module.getNamedValue(std::string("__obf_vm_retkey_") + candidate) == nullptr) {
      return candidate;
    }
  }
}

std::string make_vm_retkey_global_name(llvm::StringRef symbol_tag) {
  return ("__obf_vm_retkey_" + symbol_tag).str();
}

std::string make_vm_entry_thunk_name(llvm::Module& module,
                                     bool preserve_generated_names,
                                     llvm::StringRef source_name,
                                     std::uint64_t seed) {
  return make_vm_generated_symbol_name(module,
                                       preserve_generated_names,
                                       "__obf_vm_e",
                                       source_name,
                                       seed ^ 0xe4754ULL,
                                       "__obf_vm_entry_");
}

llvm::Value* build_hidden_token_value(llvm::IRBuilder<>& builder,
                                      llvm::Function& owner,
                                      llvm::StringRef prefix,
                                      std::uint64_t token,
                                      std::uint32_t mba_depth,
                                      std::uint64_t salt) {
  mba_config cfg;
  cfg.depth = mba_depth;
  auto context = obf::support::make_mba_context(owner, prefix, token ^ salt, cfg);
  return mba::create_opaque_integer(builder,
                                    builder.getInt64Ty(),
                                    context,
                                    llvm::APInt(64, token),
                                    salt,
                                    (prefix + ".token").str());
}

llvm::IntegerType* get_vm_pointer_int_type(llvm::Function& function) {
  llvm::Module* module = function.getParent();
  if (module == nullptr) { return nullptr; }

  const llvm::DataLayout& data_layout = module->getDataLayout();
  if (data_layout.isNonIntegralAddressSpace(function.getAddressSpace())) { return nullptr; }
  return data_layout.getIntPtrType(module->getContext(), function.getAddressSpace());
}

llvm::AttributeList build_vm_safe_callsite_attributes(const llvm::Function& callee_function) {
  return build_vm_abi_attribute_list(callee_function);
}

void sanitize_vm_implementation_attributes(llvm::Function& implementation_function,
                                           const llvm::Function& interface_function) {
  implementation_function.setAttributes(build_vm_abi_attribute_list(interface_function));
  implementation_function.setDSOLocal(true);
  implementation_function.addFnAttr(llvm::Attribute::NoInline);
}

void sanitize_vm_wrapper_attributes(llvm::Function& interface_function) {
  interface_function.setAttributes(build_vm_abi_attribute_list(interface_function));
}

llvm::Function* clone_vm_implementation(llvm::Function& interface_function,
                                        llvm::StringRef implementation_name) {
  llvm::Module* module = interface_function.getParent();
  if (module == nullptr) { return nullptr; }

  llvm::SmallVector<llvm::Type*, 8> parameter_types;
  parameter_types.reserve(interface_function.arg_size() + 1);
  for (llvm::Argument& argument : interface_function.args()) {
    parameter_types.push_back(argument.getType());
  }
  parameter_types.push_back(llvm::Type::getInt64Ty(module->getContext()));

  auto* implementation_type = llvm::FunctionType::get(
      interface_function.getReturnType(), parameter_types, /*isVarArg=*/false);
  auto* implementation_function = llvm::Function::Create(
      implementation_type, llvm::GlobalValue::InternalLinkage, implementation_name, module);
  implementation_function->setCallingConv(interface_function.getCallingConv());
  implementation_function->setDSOLocal(true);

  llvm::ValueToValueMapTy value_map;
  auto implementation_arg = implementation_function->arg_begin();
  for (llvm::Argument& argument : interface_function.args()) {
    implementation_arg->setName(argument.getName());
    value_map[&argument] = &*implementation_arg++;
  }
  implementation_arg->setName("obf.hidden_token");

  llvm::SmallVector<llvm::ReturnInst*, 8> returns;
  llvm::CloneFunctionInto(implementation_function,
                          &interface_function,
                          value_map,
                          llvm::CloneFunctionChangeType::LocalChangesOnly,
                          returns);
  if (interface_function.hasPersonalityFn()) {
    implementation_function->setPersonalityFn(interface_function.getPersonalityFn());
  }
  sanitize_vm_implementation_attributes(*implementation_function, interface_function);
  return implementation_function;
}

virtualized_function_binding
prepare_virtualized_function_binding(const function_pipeline_state& state,
                                     const obfuscation_config& config) {
  virtualized_function_binding binding;
  llvm::Function* interface_function = state.function;
  if (interface_function == nullptr || interface_function->isDeclaration()) { return binding; }
  llvm::Module* module = interface_function->getParent();
  if (module == nullptr) { return binding; }
  if (get_vm_pointer_int_type(*interface_function) == nullptr) { return binding; }

  llvm::SmallVector<llvm::CallBase*, 16> direct_call_sites;
  for (llvm::User* user : interface_function->users()) {
    auto* call = llvm::dyn_cast<llvm::CallBase>(user);
    if (call == nullptr || call->getCalledOperand()->stripPointerCasts() != interface_function) {
      continue;
    }
    direct_call_sites.push_back(call);
  }

  const vm_boundary_analysis boundary = analyze_vm_boundary(*interface_function, direct_call_sites);
  const protection_level level = state.report.decision.policy.level;
  const bool strict = requires_strict_vm_boundary(config, level);
  if (!boundary.target_supported) {
    if (strict) {
      std::string message = "vm strict boundary violation: function ";
      message += interface_function->getName().str();
      message += " cannot be virtualized safely (";
      message += boundary.target_reason;
      message += "); lower its protection level or adjust its ABI";
      llvm::report_fatal_error(llvm::StringRef(message));
    }
    return binding;
  }
  if (strict && boundary.has_preserved_site) {
    vm_incoming_site_kind preserved_kind = vm_incoming_site_kind::abi_mismatch;
    for (const vm_boundary_site& site : boundary.sites) {
      if (!site.rewritable) {
        preserved_kind = site.kind;
        break;
      }
    }
    std::string message = "vm strict boundary violation: function ";
    message += interface_function->getName().str();
    message += " has an incoming ";
    message += vm_incoming_site_kind_name(preserved_kind).str();
    message += " site that cannot be safely virtualized; rewrite the caller to an "
               "ordinary call or lower the protection level";
    llvm::report_fatal_error(llvm::StringRef(message));
  }

  const std::uint64_t seed = state.report.decision.seed;
  const bool preserve_generated_names = config.debug_preserve_generated_names;
  const llvm::StringRef source_name = interface_function->getName();
  const std::string implementation_name = make_vm_generated_symbol_name(
      *module, preserve_generated_names, "__obf_vm_i", source_name, seed, "__obf_vm_impl_");
  binding.vm_symbol_tag = make_vm_symbol_tag(*module, preserve_generated_names, source_name, seed);
  binding.target_cache_global_name = make_vm_generated_symbol_name(*module,
                                                                   preserve_generated_names,
                                                                   "__obf_vm_t",
                                                                   source_name,
                                                                   seed ^ 0x7a9ceULL,
                                                                   "__obf_vm_target_");
  binding.target_seed_global_name = make_vm_generated_symbol_name(*module,
                                                                  preserve_generated_names,
                                                                  "__obf_vm_s",
                                                                  source_name,
                                                                  seed ^ 0x5eedULL,
                                                                  "__obf_vm_targetseed_");
  binding.decode_key_global_name = make_vm_generated_symbol_name(*module,
                                                                 preserve_generated_names,
                                                                 "__obf_vm_k",
                                                                 source_name,
                                                                 seed ^ 0xdec0deULL,
                                                                 "__obf_vm_key_");
  binding.seed_case_function_name = make_vm_generated_symbol_name(*module,
                                                                  preserve_generated_names,
                                                                  "__obf_vm_c",
                                                                  source_name,
                                                                  seed ^ 0xca5eULL,
                                                                  "__obf_vm_seedcase_");
  binding.entry_thunk_function_name =
      make_vm_entry_thunk_name(*module, preserve_generated_names, source_name, seed);

  llvm::Function* implementation_function =
      clone_vm_implementation(*interface_function, implementation_name);
  if (implementation_function == nullptr) { return binding; }

  binding.interface_function = interface_function;
  binding.implementation_function = implementation_function;
  binding.state = &state;
  binding.wrapper_token =
      derive_vm_wrapper_token(state.report.decision.seed, interface_function->getName());

  std::uint64_t callsite_ordinal = 0;
  for (const vm_boundary_site& boundary_site : boundary.sites) {
    llvm::CallBase* call = boundary_site.call;
    if (call == nullptr) { continue; }
    llvm::Function* caller = call->getFunction();
    if (caller == nullptr) { continue; }

    binding.call_sites.push_back(
        {.call = call,
         .hidden_token = derive_vm_hidden_token(state.report.decision.seed,
                                                interface_function->getName(),
                                                caller->getName(),
                                                callsite_ordinal++),
         .kind = boundary_site.kind,
         .rewritable = boundary_site.rewritable});
  }

  return binding;
}

}  // namespace obf
