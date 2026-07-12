#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_BINDING_PREP_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_BINDING_PREP_H

#include "obf/plugin/internal/plugin_vm_types.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/InstrTypes.h"

#include <cstdint>
#include <string>

namespace obf {

struct function_pipeline_state;
struct obfuscation_config;

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt);

std::uint64_t derive_vm_hidden_token(std::uint64_t decision_seed,
                                     llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal);

std::uint64_t derive_vm_wrapper_token(std::uint64_t decision_seed, llvm::StringRef function_name);

std::string make_debug_vm_name(llvm::StringRef prefix, llvm::StringRef source_name);

std::string make_vm_generated_symbol_name(llvm::Module& module,
                                          bool preserve_generated_names,
                                          llvm::StringRef role,
                                          llvm::StringRef source_name,
                                          std::uint64_t seed,
                                          llvm::StringRef debug_prefix);

std::string make_vm_symbol_tag(llvm::Module& module,
                               bool preserve_generated_names,
                               llvm::StringRef source_name,
                               std::uint64_t seed);

std::string make_vm_retkey_global_name(llvm::StringRef symbol_tag);

std::string make_vm_entry_thunk_name(llvm::Module& module,
                                     bool preserve_generated_names,
                                     llvm::StringRef source_name,
                                     std::uint64_t seed);

llvm::Value* build_hidden_token_value(llvm::IRBuilder<>& builder,
                                      llvm::Function& owner,
                                      llvm::StringRef prefix,
                                      std::uint64_t token,
                                      std::uint32_t mba_depth,
                                      std::uint64_t salt);

llvm::IntegerType* get_vm_pointer_int_type(llvm::Function& function);

llvm::AttributeList build_vm_abi_attribute_list(const llvm::Function& function);

llvm::AttributeList build_vm_safe_callsite_attributes(const llvm::Function& callee_function);

void sanitize_vm_implementation_attributes(llvm::Function& implementation_function,
                                           const llvm::Function& interface_function);

void sanitize_vm_wrapper_attributes(llvm::Function& interface_function);

llvm::Function* clone_vm_implementation(llvm::Function& interface_function,
                                        llvm::StringRef implementation_name);

virtualized_function_binding
prepare_virtualized_function_binding(const function_pipeline_state& state,
                                     const obfuscation_config& config);
struct vm_boundary_site {
  llvm::CallBase* call = nullptr;
  vm_incoming_site_kind kind = vm_incoming_site_kind::ordinary_call;
  bool rewritable = true;
};

struct vm_boundary_analysis {
  bool target_supported = false;
  std::string target_reason;
  llvm::SmallVector<vm_boundary_site, 8> sites;
  bool has_preserved_site = false;
};

// Side-effect-free classification of a VM target and its incoming direct call
// sites. Must run before any cloning/extraction so an unsupported boundary
// leaves the module unmodified.
vm_boundary_analysis analyze_vm_boundary(const llvm::Function& target,
                                         llvm::ArrayRef<llvm::CallBase*> sites);

}  // namespace obf

#endif
