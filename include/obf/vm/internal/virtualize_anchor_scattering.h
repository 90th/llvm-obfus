#ifndef OBF_VM_INTERNAL_VIRTUALIZE_ANCHOR_SCATTERING_H
#define OBF_VM_INTERNAL_VIRTUALIZE_ANCHOR_SCATTERING_H

#include "obf/vm/internal/virtualize_core.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"

#include <cstdint>

namespace obf::vm {

std::uint64_t derive_vm_opaque_seed(const llvm::Function& function,
                                    const bytecode_program& program);

std::uint64_t derive_vm_return_key(const llvm::Function& function,
                                   const bytecode_program& program);

llvm::Value* build_hidden_token_seed(llvm::IRBuilder<>& builder,
                                     llvm::Argument* hidden_token_arg,
                                     std::uint64_t canonical_seed,
                                     llvm::ArrayRef<std::uint64_t> valid_tokens,
                                     const mba::builder_context& mba_context,
                                     std::uint64_t salt,
                                     llvm::StringRef name);

llvm::GlobalVariable* clone_bytecode_global_for_subhelper(llvm::GlobalVariable* bytecode_global,
                                                          std::uint32_t subhelper_index);

std::uint32_t select_bytecode_anchor_real_count(std::uint64_t bytecode_size,
                                                std::uint64_t bytecode_seed,
                                                std::uint64_t salt);

std::uint32_t select_bytecode_anchor_decoy_count(std::uint64_t bytecode_size,
                                                 std::uint64_t bytecode_seed,
                                                 std::uint64_t salt,
                                                 std::uint32_t real_count);

llvm::SmallVector<llvm::GlobalVariable*, 8> build_bytecode_anchor_globals(
    llvm::GlobalVariable* bytecode_global,
    std::uint64_t bytecode_seed,
    std::uint64_t salt,
    std::uint32_t& out_real_count,
    std::uint32_t& out_decoy_count);

void annotate_bytecode_anchor_scattering(llvm::Function& function,
                                         std::uint32_t real_count,
                                         std::uint32_t decoy_count);

vm_state_layout build_vm_state_layout(llvm::LLVMContext& context,
                                      llvm::Type* return_type,
                                      const bytecode_program& program);

llvm::Value* create_state_field_ptr(llvm::IRBuilder<>& builder,
                                    const vm_state_layout& layout,
                                    llvm::Value* state_storage,
                                    std::uint32_t field_index,
                                    llvm::StringRef name);

slot_storage build_state_slot_storage(llvm::IRBuilder<>& builder,
                                      const vm_state_layout& layout,
                                      llvm::Value* state_storage,
                                      const bytecode_program& program,
                                      llvm::StringRef name_prefix);

llvm::Value* build_hidden_token_storage_value(llvm::IRBuilder<>& builder,
                                              llvm::Argument* hidden_token_arg,
                                              std::uint64_t fallback_seed);

std::uint64_t derive_vm_bytecode_seed(const llvm::Function& function,
                                      const bytecode_program& program);
}

#endif
