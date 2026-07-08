#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_RESOLVERS_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_RESOLVERS_H

#include "obf/plugin/internal/plugin_vm_internal.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"

namespace obf {

vm_resolver_shape select_vm_resolver_shape(protection_level level);

vm_seed_resolver_shape select_vm_seed_resolver_shape(protection_level level);

vm_pointer_materialization_shape select_vm_pointer_materialization_shape(
    protection_level level, unsigned bit_width, llvm::Function& interface_function, std::uint64_t seed_base, llvm::StringRef prefix);

llvm::Value* build_encoded_vm_target_value(llvm::IRBuilder<>& builder,
                                           protection_level level,
                                           llvm::Function& owner,
                                           llvm::Function& interface_function,
                                           llvm::Function& implementation_function,
                                           llvm::GlobalVariable& target_seed_global,
                                           llvm::GlobalVariable& decode_key_global,
                                           llvm::Value* hidden_token,
                                           const llvm::APInt& key,
                                           const llvm::APInt& salt,
                                           llvm::StringRef prefix,
                                           vm_seed_resolver_shape seed_resolver_shape,
                                           std::uint64_t token_seed,
                                           std::uint64_t token_salt_base,
                                           std::uint32_t mba_depth);

llvm::Value* decode_encoded_vm_target_value(llvm::IRBuilder<>& builder,
                                            llvm::Function& owner,
                                            llvm::GlobalVariable& decode_key_global,
                                            llvm::Value* encoded_target,
                                            llvm::Value* hidden_token,
                                            const llvm::APInt& key,
                                            const llvm::APInt& salt,
                                            llvm::StringRef prefix,
                                            std::uint64_t token_seed,
                                            std::uint64_t decode_salt_base,
                                            std::uint32_t mba_depth);

llvm::APInt derive_vm_target_key(const llvm::Function& function, llvm::IntegerType* ptr_int_type);

llvm::APInt derive_vm_target_sentinel(const llvm::APInt& key);

llvm::APInt derive_vm_target_seed_mask(const llvm::Function& function,
                                       llvm::IntegerType* ptr_int_type);

llvm::GlobalVariable* get_or_create_vm_target_global(llvm::Function& function,
                                                     llvm::StringRef global_name);

llvm::GlobalVariable*
get_or_create_vm_target_seed_global(llvm::Function& interface_function,
                                    llvm::Function& implementation_function,
                                    llvm::StringRef global_name,
                                    llvm::StringRef seed_case_function_name,
                                    llvm::IntegerType* ptr_int_type,
                                    vm_seed_resolver_shape seed_resolver_shape,
                                    std::uint32_t mba_depth);

llvm::Function* get_or_create_vm_target_seed_init_function(llvm::Module& module);

llvm::Function* get_or_create_vm_target_seed_resolver(llvm::Module& module,
                                                      llvm::IntegerType* ptr_int_type);

llvm::Function* get_or_create_vm_target_seed_case_resolver(llvm::Function& interface_function,
                                                           llvm::Function& implementation_function,
                                                           llvm::StringRef resolver_name,
                                                           llvm::IntegerType* ptr_int_type,
                                                           std::uint32_t mba_depth);

void ensure_vm_target_seed_resolver_case(llvm::Function& interface_function,
                                         llvm::Function& implementation_function,
                                         llvm::StringRef resolver_name,
                                         llvm::IntegerType* ptr_int_type,
                                         std::uint32_t mba_depth);

llvm::GlobalVariable* get_or_create_vm_decode_key_global(llvm::Module& module,
                                                         llvm::IntegerType* ptr_int_type,
                                                         llvm::StringRef global_name,
                                                         const llvm::APInt& key);

llvm::Value* decode_virtualized_target_seed(llvm::IRBuilder<>& builder,
                                            protection_level level,
                                            llvm::Function& owner,
                                            llvm::StringRef prefix,
                                            llvm::Function& interface_function,
                                            llvm::Function& implementation_function,
                                            llvm::GlobalVariable& target_seed_global,
                                            llvm::Value* opaque_key,
                                            const llvm::APInt& seed_mask,
                                            vm_seed_resolver_shape seed_resolver_shape,
                                            std::uint64_t seed_base,
                                            std::uint32_t mba_depth);

llvm::Value* decode_virtualized_integer_return(llvm::IRBuilder<>& builder,
                                               llvm::Function& owner,
                                               llvm::StringRef callee_name,
                                               llvm::StringRef retkey_global_name,
                                               llvm::Value* encoded_ret,
                                               llvm::Value* hidden_token,
                                               std::uint64_t token_seed,
                                               std::uint32_t mba_depth);
}

#endif
