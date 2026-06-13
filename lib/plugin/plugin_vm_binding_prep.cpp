#include "obf/plugin/internal/plugin_vm_binding_prep.h"

#include "obf/plugin/obfuscator_plugin_internal.h"

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
#include "llvm/Transforms/Utils/Cloning.h"

#include <string>

namespace obf {

namespace {

bool is_vm_abi_safe_return_attribute(llvm::Attribute attribute) {
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }

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
  if (attribute.isStringAttribute() || !attribute.hasKindAsEnum()) { return false; }

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

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::uint64_t derive_vm_hidden_token(llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal) {
  std::uint64_t seed = stable_hash_string(callee_name);
  seed = mix_vm_handshake_seed(seed, stable_hash_string(caller_name));
  seed = mix_vm_handshake_seed(seed, ordinal + 1);
  return seed == 0 ? 0xa55aa55aa55aa55aULL : seed;
}

std::uint64_t derive_vm_wrapper_token(llvm::StringRef function_name) {
  return derive_vm_hidden_token(function_name, function_name, 0x51f15eedULL);
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
  return make_vm_generated_symbol_name(
      module, preserve_generated_names, "__obf_vm_e", source_name, seed ^ 0xe4754ULL,
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
  binding.wrapper_token = derive_vm_wrapper_token(interface_function->getName());

  std::uint64_t callsite_ordinal = 0;
  for (llvm::CallBase* call : direct_call_sites) {
    llvm::Function* caller = call->getFunction();
    if (caller == nullptr) { continue; }

    binding.call_sites.push_back(
        {.call = call,
         .hidden_token = derive_vm_hidden_token(
             interface_function->getName(), caller->getName(), callsite_ordinal++)});
  }

  return binding;
}

}  // namespace obf
