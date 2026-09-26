#include "obf/support/flattening_metadata.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

namespace obf::flattening {

namespace {

std::optional<block_role> get_block_role(const llvm::BasicBlock& block) {
  const llvm::Instruction* terminator = block.getTerminator();
  if (terminator == nullptr) { return std::nullopt; }

  const llvm::MDNode* node = terminator->getMetadata(kFlattenedBlockMD);
  if (node == nullptr || node->getNumOperands() < 2) { return std::nullopt; }

  const auto* role_value = llvm::mdconst::dyn_extract<llvm::ConstantInt>(node->getOperand(1));
  if (role_value == nullptr) { return std::nullopt; }

  return static_cast<block_role>(role_value->getZExtValue());
}

}  // namespace

bool is_generated_block(const llvm::BasicBlock& block) {
  const std::optional<block_role> role = get_block_role(block);
  if (!role.has_value()) { return false; }

  switch (*role) {
    case block_role::root_dispatch:
    case block_role::dispatch_split:
    case block_role::dispatch_left:
    case block_role::dispatch_right:
    case block_role::dispatch_leaf:
    case block_role::edge:
    case block_role::decoy:
    case block_role::setup:
      return true;
    case block_role::handler:
    case block_role::terminal:
      return false;
  }

  return false;
}

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
