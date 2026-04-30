#include "obf/analysis/function_features.h"

#include "obf/analysis/annotation_utils.h"

#include "llvm/Analysis/CFG.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"

#include <utility>

namespace obf {

namespace {

bool has_non_annotation_address_taken(const llvm::Function &function) {
  for (const llvm::Use &use : function.uses()) {
    if (const auto *call = llvm::dyn_cast<llvm::CallBase>(use.getUser())) {
      if (call->isCallee(&use)) {
        continue;
      }
    }

    if (!is_annotation_user(use.getUser())) {
      return true;
    }
  }

  return false;
}

bool references_string_literal(const llvm::Instruction &instruction) {
  for (const llvm::Use &use : instruction.operands()) {
    const llvm::Value *operand = use.get();
    const llvm::Value *stripped = operand->stripPointerCasts();
    const auto *global = llvm::dyn_cast<llvm::GlobalVariable>(stripped);

    if (global == nullptr || !global->hasInitializer()) {
      continue;
    }

    const auto *data = llvm::dyn_cast<llvm::ConstantDataSequential>(
        global->getInitializer());
    if (data != nullptr && data->isString()) {
      return true;
    }
  }

  return false;
}

std::size_t count_cfg_edges(const llvm::Function &function) {
  std::size_t edge_count = 0;

  for (const llvm::BasicBlock &block : function) {
    edge_count += llvm::succ_size(&block);
  }

  return edge_count;
}

} // namespace

function_features collect_function_features(const llvm::Function &function) {
  function_features features;
  features.name = function.getName().str();
  features.address_taken = has_non_annotation_address_taken(function);
  features.is_declaration = function.isDeclaration();

  if (features.is_declaration) {
    return features;
  }

  features.basic_block_count = function.size();

  llvm::SmallVector<std::pair<const llvm::BasicBlock *, const llvm::BasicBlock *>,
                    8>
      backedges;
  llvm::FindFunctionBackedges(function, backedges);
  features.has_loops = !backedges.empty();

  const std::size_t edge_count = count_cfg_edges(function);
  features.cyclomatic_complexity =
      edge_count >= features.basic_block_count
          ? edge_count - features.basic_block_count + 2
          : 1;

  for (const llvm::BasicBlock &block : function) {
    features.has_exception_edges =
        features.has_exception_edges || block.isEHPad();

    for (const llvm::Instruction &instruction : block) {
      ++features.instruction_count;

      if (llvm::isa<llvm::InvokeInst>(instruction)) {
        features.has_exception_edges = true;
      }

      if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
        ++features.call_count;

        if (call->isInlineAsm()) {
          features.has_inline_asm = true;
        }

        if (const llvm::Function *callee = call->getCalledFunction()) {
          if (callee == &function) {
            features.is_recursive = true;
          }
        }
      }

      if (instruction.getType()->isVectorTy()) {
        features.has_vector_ops = true;
      }

      for (const llvm::Use &use : instruction.operands()) {
        if (use->getType()->isVectorTy()) {
          features.has_vector_ops = true;
          break;
        }
      }

      if (references_string_literal(instruction)) {
        ++features.string_ref_count;
      }
    }
  }

  return features;
}

} // namespace obf
