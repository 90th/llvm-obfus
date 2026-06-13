#include "obf/support/flattening_metadata.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

namespace obf::flattening {

llvm::MDNode* tag_block(llvm::BasicBlock& block, block_role role) {
  auto& ctx = block.getContext();
  llvm::Metadata* md_args[] = {
    llvm::MDString::get(ctx, kFlattenedBlockMD),
    llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
      llvm::Type::getInt32Ty(ctx), static_cast<uint32_t>(role)))
  };
  auto* node = llvm::MDNode::get(ctx, md_args);
  block.getTerminator()->setMetadata(kFlattenedBlockMD, node);
  return node;
}

llvm::MDNode* tag_function(llvm::Function& function) {
  auto& ctx = function.getContext();
  llvm::Metadata* version_args[] = {
    llvm::MDString::get(ctx, "obf.flattened.version"),
    llvm::ConstantAsMetadata::get(llvm::ConstantInt::get(
      llvm::Type::getInt32Ty(ctx), 1))
  };
  auto* version_node = llvm::MDNode::get(ctx, version_args);

  llvm::Metadata* fn_args[] = {
    llvm::MDString::get(ctx, kFlattenedMD),
    version_node
  };
  auto* node = llvm::MDNode::get(ctx, fn_args);
  function.setMetadata(kFlattenedMD, node);
  return node;
}

}  // namespace obf::flattening
