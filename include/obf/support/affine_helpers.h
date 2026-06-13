#pragma once

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/IRBuilder.h"

#include <cstdint>

namespace obf::support {

llvm::APInt make_odd_affine_multiplier(unsigned bit_width, std::uint64_t seed);
llvm::APInt compute_mod_inverse_pow2(const llvm::APInt& multiplier);
llvm::APInt make_affine_bias(unsigned bit_width, std::uint64_t seed);
llvm::Value* rotate_left_scalar(llvm::IRBuilderBase& builder,
                                llvm::Value* value,
                                unsigned amt,
                                llvm::StringRef name);
llvm::Value* rotate_right_scalar(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 unsigned amt,
                                 llvm::StringRef name);
llvm::Value* build_affine_encode(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& mul,
                                 const llvm::APInt& add,
                                 llvm::StringRef name);
llvm::Value* build_affine_decode(llvm::IRBuilderBase& builder,
                                 llvm::Value* value,
                                 const llvm::APInt& mul,
                                 const llvm::APInt& add,
                                 llvm::StringRef name);

}  // namespace obf::support
