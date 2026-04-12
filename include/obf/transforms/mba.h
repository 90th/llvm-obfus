#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace llvm {
class AllocaInst;
class Function;
class Type;
class Value;
} // namespace llvm

namespace obf::mba {

inline constexpr std::uint32_t max_mba_depth = 5;

struct builder_context {
  llvm::AllocaInst *seed_slot_a = nullptr;
  llvm::AllocaInst *seed_slot_b = nullptr;
  std::uint64_t seed_base = 0;
  std::uint32_t depth = 1;
};

builder_context get_or_create_builder_context(llvm::Function &function,
                                              llvm::StringRef prefix,
                                              std::uint64_t seed_base);

llvm::Value *create_add(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name = {});

llvm::Value *create_sub(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name = {});

llvm::Value *create_xor(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                        llvm::Value *rhs, const builder_context &context,
                        std::uint64_t salt, llvm::StringRef name = {});

} // namespace obf::mba
