#pragma once

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/User.h"

namespace obf {

/// \brief Recursively check if a value is part of llvm.global.annotations chain.
/// 
/// Determines whether a user is part of the LLVM IR annotation infrastructure
/// by recursively walking the use-chain. Used to identify annotation-related
/// values for filtering in transforms.
/// 
/// The annotation system uses nested constants and the global "llvm.global.annotations"
/// variable. This function recursively checks if the given user is part of that chain.
/// 
/// \param user Pointer to an IR user (value with users)
/// \return true if user is part of annotation infrastructure, false otherwise
/// \note Recursive: expensive for large use-chains; cache results if called repeatedly
/// \note Returns true if user is llvm.global.annotations global variable
inline bool is_annotation_user(const llvm::User *user) {
  if (const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(user)) {
    return global->getName() == "llvm.global.annotations";
  }

  if (!llvm::isa<llvm::Constant>(user) || user->user_empty()) {
    return false;
  }

  for (const llvm::User *parent : user->users()) {
    if (!is_annotation_user(parent)) {
      return false;
    }
  }

  return true;
}

} // namespace obf