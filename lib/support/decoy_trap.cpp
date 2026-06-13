#include "obf/support/decoy_trap.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace obf::support {

decoy_loop_state build_decoy_loop_core(llvm::IRBuilderBase& builder,
                                       llvm::PHINode* state,
                                       llvm::PHINode* iter,
                                       llvm::StringRef prefix) {
  llvm::Value* rotl_shl = builder.CreateShl(
      state, llvm::ConstantInt::get(builder.getInt64Ty(), 13), (prefix + ".rotl.shl").str());
  llvm::Value* rotl_lshr = builder.CreateLShr(
      state, llvm::ConstantInt::get(builder.getInt64Ty(), 51), (prefix + ".rotl.lshr").str());
  llvm::Value* rotl = builder.CreateOr(rotl_shl, rotl_lshr, (prefix + ".rotl").str());
  llvm::Value* mixed = builder.CreateXor(
      rotl, llvm::ConstantInt::get(builder.getInt64Ty(), 0x9e3779b97f4a7c15ULL),
      (prefix + ".mix").str());
  llvm::Value* multiplied = builder.CreateMul(
      mixed, llvm::ConstantInt::get(builder.getInt64Ty(), 0x94d049bb133111ebULL),
      (prefix + ".mul").str());
  llvm::Value* iteration64 =
      builder.CreateZExt(iter, builder.getInt64Ty(), (prefix + ".iter64").str());
  llvm::Value* next_state =
      builder.CreateXor(multiplied, iteration64, (prefix + ".state.next").str());
  llvm::Value* next_iteration = builder.CreateAdd(
      iter, llvm::ConstantInt::get(builder.getInt32Ty(), 1), (prefix + ".iter.next").str());

  return {state, iter, next_state, next_iteration};
}

}  // namespace obf::support
