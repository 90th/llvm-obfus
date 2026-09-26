#include "obf/transforms/instruction_substitution.h"

#include "obf/support/flattening_metadata.h"
#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/support/value_utils.h"
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

template <typename FunctionT, typename CallbackT>
std::size_t
visit_candidate_instructions(FunctionT& function, std::size_t limit, CallbackT&& callback) {
  if (limit == 0) { return 0; }

  std::size_t count = 0;
  for (auto& block : function) {
    if (obf::flattening::is_generated_block(block)) { continue; }
    for (auto& instruction : block) {
      auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary == nullptr || !is_supported_instruction(*binary)) { continue; }

      callback(binary);
      ++count;
      if (count >= limit) { return count; }
    }
  }

  return count;
}

instruction_substitution_result make_candidate_detail(std::size_t count) {
  if (count == 0) { return {.substitution_count = 0, .detail = "no eligible binary operators"}; }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) available"};
}

llvm::BinaryOperator* resolve_candidate_site(llvm::Function& function,
                                             const instruction_substitution_site& candidate) {
  auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(candidate);
  if (binary == nullptr || binary->getParent() == nullptr || binary->getFunction() != &function ||
      obf::flattening::is_generated_block(*binary->getParent()) ||
      !is_supported_instruction(*binary)) {
    return nullptr;
  }

  return binary;
}

instruction_substitution_result analyze_impl(const llvm::Function& function,
                                             const instruction_substitution_options& options) {
  if (function.isDeclaration()) { return {.substitution_count = 0, .detail = "declaration"}; }

  if (options.max_substitutions_per_function == 0) {
    return {.substitution_count = 0, .detail = "max_substitutions_per_function is zero"};
  }

  const std::size_t count = visit_candidate_instructions(
      function, options.max_substitutions_per_function, [](const auto*) {});
  return make_candidate_detail(count);
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

instruction_substitution_sites
collect_instruction_substitution_sites(llvm::Function& function,
                                       const instruction_substitution_options& options) {
  instruction_substitution_sites sites;
  if (function.isDeclaration() || options.max_substitutions_per_function == 0) { return sites; }

  visit_candidate_instructions(
      function, options.max_substitutions_per_function, [&](llvm::BinaryOperator* candidate) {
        sites.push_back(candidate);
      });
  return sites;
}

instruction_substitution_result
run_instruction_substitution(llvm::Function& function,
                             const instruction_substitution_options& options) {
  const instruction_substitution_result analysis = analyze_impl(function, options);
  if (analysis.substitution_count == 0) { return analysis; }

  const instruction_substitution_sites candidates =
      collect_instruction_substitution_sites(function, options);
  return run_instruction_substitution(function, options, candidates);
}

instruction_substitution_result
run_instruction_substitution(llvm::Function& function,
                             const instruction_substitution_options& options,
                             llvm::ArrayRef<instruction_substitution_site> candidates) {
  if (function.isDeclaration()) { return {.substitution_count = 0, .detail = "declaration"}; }

  if (options.max_substitutions_per_function == 0) {
    return {.substitution_count = 0, .detail = "max_substitutions_per_function is zero"};
  }

  const std::uint64_t function_seed =
      mix_seed(options.seed, stable_hash_string(function.getName()));
  std::optional<mba::builder_context> ctx;

  std::size_t count = 0;
  std::size_t padded = 0;
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    if (count >= options.max_substitutions_per_function) { break; }

    llvm::BinaryOperator* binary = resolve_candidate_site(function, candidates[i]);
    if (binary == nullptr) { continue; }

    const std::uint64_t site_seed = mix_seed(function_seed, i + 1);
    const bool family = (site_seed & 1ULL) != 0ULL;

    llvm::IRBuilder<> builder(binary);
    support::stabilized_value stable_lhs{.value = binary->getOperand(0)};
    support::stabilized_value stable_rhs{.value = binary->getOperand(1)};
    const bool duplicates_operands = binary->getOpcode() == llvm::Instruction::Xor || family;
    if (duplicates_operands) {
      stable_lhs =
          support::stabilize_value_for_reuse(builder, stable_lhs.value, "obf.subst.lhs");
      stable_rhs =
          support::stabilize_value_for_reuse(builder, stable_rhs.value, "obf.subst.rhs");
    }

    llvm::Value* replacement = nullptr;
    switch (binary->getOpcode()) {
      case llvm::Instruction::And:
        replacement = substitute_and(builder, stable_lhs.value, stable_rhs.value, family);
        break;
      case llvm::Instruction::Or:
        replacement = substitute_or(builder, stable_lhs.value, stable_rhs.value, family);
        break;
      case llvm::Instruction::Xor:
        replacement = substitute_xor(builder, stable_lhs.value, stable_rhs.value, family);
        break;
      default:
        break;
    }

    if (replacement == nullptr) { continue; }

    if (padded < options.max_padded_sites && options.mba_depth >= 1 &&
        replacement->getType()->isIntegerTy()) {
      if (!ctx.has_value()) {
        ctx = obf::support::make_mba_context(function,
                                             "obf.subst",
                                             function_seed,
                                             {options.mba_depth,
                                              options.mba_max_ir_instructions,
                                              options.mba_enable_polynomial,
                                              options.mba_enable_multiplication});
      }

      auto* padded_type = llvm::cast<llvm::IntegerType>(replacement->getType());
      llvm::Value* zero = mba::create_opaque_integer(builder,
                                                     padded_type,
                                                     *ctx,
                                                     llvm::APInt(padded_type->getBitWidth(), 0),
                                                     site_seed,
                                                     "obf.subst.pad.zero");
      replacement =
          ((site_seed >> 1) & 1ULL) != 0ULL
              ? mba::create_xor(builder, replacement, zero, *ctx, site_seed, "obf.subst.pad")
              : mba::create_add(builder, replacement, zero, *ctx, site_seed, "obf.subst.pad");
      ++padded;
    }
    if (duplicates_operands) {
      const support::stabilized_value operands[] = {stable_lhs, stable_rhs};
      replacement = support::restore_poison_from_stabilized_values(
          builder, replacement, operands, "obf.subst");
    }

    replacement->takeName(binary);
    binary->replaceAllUsesWith(replacement);
    binary->eraseFromParent();
    ++count;
  }

  if (count == 0) { return make_candidate_detail(0); }

  return {.substitution_count = count,
          .detail = std::to_string(count) + " substitution(s) applied"};
}

}  // namespace obf
