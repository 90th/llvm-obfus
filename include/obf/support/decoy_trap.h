#pragma once

#include "llvm/ADT/StringRef.h"

#include <cstdint>

namespace llvm {
class BasicBlock;
class Function;
class IRBuilderBase;
class PHINode;
class Value;
}  // namespace llvm

namespace obf::support {

struct decoy_loop_state {
  llvm::PHINode* state_phi;
  llvm::PHINode* iter_phi;
  llvm::Value* next_state;
  llvm::Value* next_iteration;
};

decoy_loop_state build_decoy_loop_core(llvm::IRBuilderBase& builder,
                                       llvm::PHINode* state,
                                       llvm::PHINode* iter,
                                       llvm::StringRef prefix);

}  // namespace obf::support
