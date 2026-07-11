#include "obf/transforms/instruction_substitution.h"

#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/APInt.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace obf {

namespace {

bool is_supported_instruction(const llvm::BinaryOperator& instruction) {
  if (!instruction.getType()->isIntegerTy()) { return false; }

  switch (instruction.getOpcode()) {
    case llvm::Instruction::And:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
      return true;
    default:
      return false;
  }
}

instruction_substitution_result analyze_impl(const llvm::Function& function,
                                             const instruction_substitution_options& options) {
  if (function.isDeclaration()) { return {.substitution_count = 0, .detail = "declaration"}; }

  if (options.max_substitutions_per_function == 0) {
    return {.substitution_count = 0, .detail = "max_substitutions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary == nullptr || !is_supported_instruction(*binary)) { continue; }

      ++count;
      if (count >= options.max_substitutions_per_function) {
        return {.substitution_count = count,
                .detail = std::to_string(count) + " substitution(s) available"};
      }
    }
  }

  if (count == 0) { return {.substitution_count = 0, .detail = "no eligible binary operators"}; }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) available"};
}

llvm::Value* substitute_and(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            bool family) {
  if (!family) {
    llvm::Value* not_lhs = builder.CreateNot(lhs, "obf.and.notlhs");
    llvm::Value* not_rhs = builder.CreateNot(rhs, "obf.and.notrhs");
    llvm::Value* or_part = builder.CreateOr(not_lhs, not_rhs, "obf.and.or");
    return builder.CreateNot(or_part, "obf.and");
  }
  llvm::Value* or_part = builder.CreateOr(lhs, rhs, "obf.and.or2");
  llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.and.xor2");
  return builder.CreateSub(or_part, xor_part, "obf.and");
}

llvm::Value* substitute_or(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                           bool family) {
  if (!family) {
    llvm::Value* not_lhs = builder.CreateNot(lhs, "obf.or.notlhs");
    llvm::Value* not_rhs = builder.CreateNot(rhs, "obf.or.notrhs");
    llvm::Value* and_part = builder.CreateAnd(not_lhs, not_rhs, "obf.or.and");
    return builder.CreateNot(and_part, "obf.or");
  }
  llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.or.and2");
  llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "obf.or.xor2");
  return builder.CreateAdd(and_part, xor_part, "obf.or");
}

llvm::Value* substitute_xor(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            bool family) {
  if (!family) {
    llvm::Value* or_part = builder.CreateOr(lhs, rhs, "obf.xor.or");
    llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "obf.xor.and");
    return builder.CreateSub(or_part, and_part, "obf.xor");
  }
  llvm::Value* not_rhs = builder.CreateNot(rhs, "obf.xor.notrhs");
  llvm::Value* lhs_mask = builder.CreateAnd(lhs, not_rhs, "obf.xor.lhsmask");
  llvm::Value* not_lhs = builder.CreateNot(lhs, "obf.xor.notlhs");
  llvm::Value* rhs_mask = builder.CreateAnd(not_lhs, rhs, "obf.xor.rhsmask");
  return builder.CreateOr(lhs_mask, rhs_mask, "obf.xor");
}

}  // namespace

instruction_substitution_result
analyze_instruction_substitution(const llvm::Function& function,
                                 const instruction_substitution_options& options) {
  return analyze_impl(function, options);
}

instruction_substitution_result
run_instruction_substitution(llvm::Function& function,
                             const instruction_substitution_options& options) {
  const instruction_substitution_result analysis = analyze_impl(function, options);
  if (analysis.substitution_count == 0) { return analysis; }

  llvm::SmallVector<llvm::BinaryOperator*, 16> candidates;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary != nullptr && is_supported_instruction(*binary)) { candidates.push_back(binary); }
    }
  }

  const std::uint64_t function_seed =
      mix_seed(options.seed, stable_hash_string(function.getName()));
  auto ctx = obf::support::make_mba_context(
      function,
      "obf.subst",
      function_seed,
      {options.mba_depth,
       options.mba_max_ir_instructions,
       options.mba_enable_polynomial,
       options.mba_enable_multiplication});

  std::size_t count = 0;
  std::size_t padded = 0;
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    llvm::BinaryOperator* binary = candidates[i];
    if (count >= options.max_substitutions_per_function || binary == nullptr) { break; }

    const std::uint64_t site_seed = mix_seed(function_seed, i + 1);
    const bool family = (site_seed & 1ULL) != 0ULL;

    llvm::IRBuilder<> builder(binary);
    llvm::Value* replacement = nullptr;
    switch (binary->getOpcode()) {
      case llvm::Instruction::And:
        replacement = substitute_and(builder, binary->getOperand(0), binary->getOperand(1), family);
        break;
      case llvm::Instruction::Or:
        replacement = substitute_or(builder, binary->getOperand(0), binary->getOperand(1), family);
        break;
      case llvm::Instruction::Xor:
        replacement = substitute_xor(builder, binary->getOperand(0), binary->getOperand(1), family);
        break;
      default:
        break;
    }

    if (replacement == nullptr) { continue; }

    if (padded < options.max_padded_sites && options.mba_depth >= 1 &&
        replacement->getType()->isIntegerTy()) {
      auto* padded_type = llvm::cast<llvm::IntegerType>(replacement->getType());
      llvm::Value* zero = mba::create_opaque_integer(
          builder, padded_type, ctx, llvm::APInt(padded_type->getBitWidth(), 0), site_seed,
          "obf.subst.pad.zero");
      replacement =
          ((site_seed >> 1) & 1ULL) != 0ULL
              ? mba::create_xor(builder, replacement, zero, ctx, site_seed, "obf.subst.pad")
              : mba::create_add(builder, replacement, zero, ctx, site_seed, "obf.subst.pad");
      ++padded;
    }

    replacement->takeName(binary);
    binary->replaceAllUsesWith(replacement);
    binary->eraseFromParent();
    ++count;
  }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) applied"};
}

}  // namespace obf
