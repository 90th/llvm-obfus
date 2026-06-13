#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_WRAPPER_EMISSION_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_WRAPPER_EMISSION_H

#include "obf/plugin/internal/plugin_vm_internal.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"

#include <cstddef>
#include <cstdint>

namespace obf {

vm_entry_thunk_shape select_vm_entry_thunk_shape(llvm::StringRef source_name,
                                                 std::uint64_t seed);

void rebalance_vm_entry_thunk_shapes(llvm::Module& module,
                                     llvm::ArrayRef<virtualized_function_binding*> bindings,
                                     llvm::SmallVectorImpl<vm_entry_thunk_shape>& shapes);

llvm::CallInst* emit_vm_entry_thunk_call(llvm::IRBuilder<>& builder,
                                         llvm::Function& interface_function,
                                         llvm::Function& implementation_function,
                                         llvm::ArrayRef<llvm::Value*> forward_args);

llvm::CallInst* emit_vm_entry_thunk_indirect_call(llvm::IRBuilder<>& builder,
                                                  llvm::Function& interface_function,
                                                  llvm::Function& implementation_function,
                                                  llvm::StringRef thunk_name,
                                                  llvm::ArrayRef<llvm::Value*> forward_args,
                                                  llvm::StringRef name_prefix,
                                                  std::uint64_t salt);

void emit_vm_entry_thunk_call_and_return(llvm::IRBuilder<>& builder,
                                         llvm::Function& interface_function,
                                         llvm::Function& implementation_function,
                                         llvm::ArrayRef<llvm::Value*> forward_args);

llvm::Function* create_vm_entry_thunk(llvm::Function& interface_function,
                                      llvm::Function& implementation_function,
                                      llvm::StringRef thunk_name,
                                      vm_entry_thunk_shape shape);

void rewrite_vm_interface_wrapper(llvm::Function& interface_function,
                                  llvm::Function& implementation_function,
                                  const virtualized_function_binding& binding,
                                  std::uint64_t wrapper_token,
                                  vm_resolver_shape resolver_shape,
                                  vm_seed_resolver_shape seed_resolver_shape,
                                  std::uint32_t mba_depth);
}

#endif
