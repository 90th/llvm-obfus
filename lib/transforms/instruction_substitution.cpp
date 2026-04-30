#include "obf/transforms/instruction_substitution.h"

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

#include <cstdint>

namespace obf {

namespace {

bool is_supported_instruction(const llvm::BinaryOperator &instruction) {
  if (!instruction.getType()->isIntegerTy()) {
    return false;
  }

  switch (instruction.getOpcode()) {
  case llvm::Instruction::Add:
  case llvm::Instruction::Sub:
    return !instruction.hasNoSignedWrap() && !instruction.hasNoUnsignedWrap();
  case llvm::Instruction::Xor:
  case llvm::Instruction::And:
  case llvm::Instruction::Or:
    return true;
  default:
    return false;
  }
}

std::uint64_t derive_mba_seed(const llvm::Function &function) {
  std::uint64_t seed = stable_hash_string(function.getName());
  return seed == 0 ? 0x4cf5ad432745937fULL : seed;
}

instruction_substitution_result
analyze_impl(const llvm::Function &function,
             const instruction_substitution_options &options) {
  if (function.isDeclaration()) {
    return {.substitution_count = 0, .detail = "declaration"};
  }

  if (options.max_substitutions_per_function == 0) {
    return {.substitution_count = 0,
            .detail = "max_substitutions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock &block : function) {
    for (const llvm::Instruction &instruction : block) {
      const auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary == nullptr || !is_supported_instruction(*binary)) {
        continue;
      }

      ++count;
      if (count >= options.max_substitutions_per_function) {
        return {.substitution_count = count,
                .detail = std::to_string(count) +
                          " substitution(s) available"};
      }
    }
  }

  if (count == 0) {
    return {.substitution_count = 0, .detail = "no eligible binary operators"};
  }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) available"};
}

llvm::Value *substitute_add(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                            llvm::Value *rhs,
                            const mba::builder_context &mba_context,
                            std::uint64_t salt) {
  return mba::create_add(builder, lhs, rhs, mba_context, salt, "obf.add");
}

llvm::Value *substitute_sub(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                            llvm::Value *rhs,
                            const mba::builder_context &mba_context,
                            std::uint64_t salt) {
  return mba::create_sub(builder, lhs, rhs, mba_context, salt, "obf.sub");
}

llvm::Value *substitute_xor(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                            llvm::Value *rhs,
                            const mba::builder_context &mba_context,
                            std::uint64_t salt) {
  return mba::create_xor(builder, lhs, rhs, mba_context, salt, "obf.xor");
}

llvm::Value *substitute_and(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                            llvm::Value *rhs) {
  llvm::Value *not_lhs = builder.CreateNot(lhs, "obf.and.notlhs");
  llvm::Value *not_rhs = builder.CreateNot(rhs, "obf.and.notrhs");
  llvm::Value *or_part = builder.CreateOr(not_lhs, not_rhs, "obf.and.or");
  return builder.CreateNot(or_part, "obf.and");
}

llvm::Value *substitute_or(llvm::IRBuilder<> &builder, llvm::Value *lhs,
                           llvm::Value *rhs) {
  llvm::Value *not_lhs = builder.CreateNot(lhs, "obf.or.notlhs");
  llvm::Value *not_rhs = builder.CreateNot(rhs, "obf.or.notrhs");
  llvm::Value *and_part = builder.CreateAnd(not_lhs, not_rhs, "obf.or.and");
  return builder.CreateNot(and_part, "obf.or");
}

} // namespace

instruction_substitution_result
analyze_instruction_substitution(const llvm::Function &function,
                                 const instruction_substitution_options &options) {
  return analyze_impl(function, options);
}

instruction_substitution_result
run_instruction_substitution(llvm::Function &function,
                             const instruction_substitution_options &options) {
  const instruction_substitution_result analysis = analyze_impl(function, options);
  if (analysis.substitution_count == 0) {
    return analysis;
  }

  llvm::SmallVector<llvm::BinaryOperator *, 16> candidates;
  for (llvm::BasicBlock &block : function) {
    for (llvm::Instruction &instruction : block) {
      auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary != nullptr && is_supported_instruction(*binary)) {
        candidates.push_back(binary);
      }
    }
  }

  mba::builder_context mba_context =
      mba::get_or_create_builder_context(function, "obf.mba",
                                         derive_mba_seed(function));
  mba_context.depth = options.mba_depth;
  std::size_t count = 0;
  for (llvm::BinaryOperator *binary : candidates) {
    if (count >= options.max_substitutions_per_function || binary == nullptr) {
      break;
    }

    llvm::IRBuilder<> builder(binary);
    llvm::Value *replacement = nullptr;
    switch (binary->getOpcode()) {
    case llvm::Instruction::Add:
      replacement = substitute_add(builder, binary->getOperand(0),
                                   binary->getOperand(1), mba_context,
                                   count + 1);
      break;
    case llvm::Instruction::Sub:
      replacement = substitute_sub(builder, binary->getOperand(0),
                                   binary->getOperand(1), mba_context,
                                   count + 1);
      break;
    case llvm::Instruction::Xor:
      replacement = substitute_xor(builder, binary->getOperand(0),
                                   binary->getOperand(1), mba_context,
                                   count + 1);
      break;
    case llvm::Instruction::And:
      replacement = substitute_and(builder, binary->getOperand(0),
                                   binary->getOperand(1));
      break;
    case llvm::Instruction::Or:
      replacement = substitute_or(builder, binary->getOperand(0),
                                  binary->getOperand(1));
      break;
    default:
      break;
    }

    if (replacement == nullptr) {
      continue;
    }

    replacement->takeName(binary);
    binary->replaceAllUsesWith(replacement);
    binary->eraseFromParent();
    ++count;
  }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) applied"};
}

} // namespace obf
