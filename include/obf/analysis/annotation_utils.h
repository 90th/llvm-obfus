#pragma once

#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/User.h"

namespace obf {

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