#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_BINDING_PREP_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_BINDING_PREP_H

#include "obf/plugin/internal/plugin_vm_types.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

#include <cstdint>
#include <string>

namespace obf {

struct function_pipeline_state;
struct obfuscation_config;

std::uint64_t mix_vm_handshake_seed(std::uint64_t seed, std::uint64_t salt);

std::uint64_t derive_vm_hidden_token(llvm::StringRef callee_name,
                                     llvm::StringRef caller_name,
                                     std::uint64_t ordinal);

std::uint64_t derive_vm_wrapper_token(llvm::StringRef function_name);

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
}

#endif
