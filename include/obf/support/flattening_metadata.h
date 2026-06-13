#pragma once
#include "llvm/ADT/StringRef.h"
#include <cstdint>
#include <optional>

namespace llvm {
class BasicBlock;
class Function;
class Instruction;
class LLVMContext;
class MDNode;
class Value;
}  // namespace llvm

namespace obf::flattening {

constexpr llvm::StringLiteral kFlattenedMD = "obf.flattened";
constexpr llvm::StringLiteral kFlattenedBlockMD = "obf.flattened.block";

enum class block_role : uint32_t {
  root_dispatch = 0,
  dispatch_split = 1,
  dispatch_left = 2,
  dispatch_right = 3,
  dispatch_leaf = 4,
  edge = 5,
  decoy = 6,
  setup = 7,
  handler = 8,
  terminal = 9,
};

llvm::MDNode* tag_block(llvm::BasicBlock& block, block_role role);

llvm::MDNode* tag_function(llvm::Function& function);

}  // namespace obf::flattening
