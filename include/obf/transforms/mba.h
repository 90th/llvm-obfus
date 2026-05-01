#pragma once

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace llvm {
class Function;
class GlobalVariable;
class IntegerType;
class Module;
class Type;
class Value;
}  // namespace llvm

namespace obf::mba {

inline constexpr std::uint32_t max_mba_depth = 5;

struct builder_context {
  llvm::GlobalVariable* entropy_anchor = nullptr;
  std::uint64_t seed_base = 0;
  std::uint32_t depth = 1;
};

llvm::GlobalVariable* get_or_create_entropy_anchor(llvm::Module& module);

builder_context get_or_create_builder_context(llvm::Function& function,
                                              llvm::StringRef prefix,
                                              std::uint64_t seed_base);

llvm::Value* entangle_value(llvm::IRBuilder<>& builder,
                            llvm::Value* value,
                            const builder_context& context,
                            std::uint64_t salt,
                            llvm::StringRef name = {});

llvm::Value* create_opaque_integer(llvm::IRBuilder<>& builder,
                                   llvm::IntegerType* type,
                                   const builder_context& context,
                                   const llvm::APInt& value,
                                   std::uint64_t salt,
                                   llvm::StringRef name = {});

llvm::Value* create_add(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name = {});

llvm::Value* create_sub(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name = {});

llvm::Value* create_xor(llvm::IRBuilder<>& builder,
                        llvm::Value* lhs,
                        llvm::Value* rhs,
                        const builder_context& context,
                        std::uint64_t salt,
                        llvm::StringRef name = {});

llvm::Value* build_entropy_true_predicate(llvm::IRBuilder<>& builder,
                                          llvm::Function& function,
                                          std::uint32_t mba_depth,
                                          std::uint64_t salt_base,
                                          std::uint64_t context_a_salt,
                                          std::uint64_t context_b_salt,
                                          llvm::StringRef context_a_name,
                                          llvm::StringRef context_b_name,
                                          llvm::StringRef result_name = "obf.opaque.true");

}  // namespace obf::mba
