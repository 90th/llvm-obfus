#include "obf/transforms/zero_comparison.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <string>

namespace obf {

namespace {

enum class comparison_site_kind { integer, string, select };

bool is_equality_icmp(const llvm::ICmpInst& compare) {
  return compare.getPredicate() == llvm::ICmpInst::ICMP_EQ ||
         compare.getPredicate() == llvm::ICmpInst::ICMP_NE;
}

bool is_supported_comparison(const llvm::ICmpInst& compare) {
  if (!is_equality_icmp(compare)) { return false; }
  const llvm::Type* type = compare.getOperand(0)->getType();
  return type->isIntegerTy() || type->isPointerTy();
}

llvm::IntegerType* comparison_integer_type(llvm::IRBuilder<>& builder, llvm::Value* value) {
  if (auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(value->getType())) {
    return integer_type;
  }
  if (!value->getType()->isPointerTy()) { return nullptr; }
  const llvm::DataLayout& layout = builder.GetInsertBlock()->getModule()->getDataLayout();
  return llvm::cast<llvm::IntegerType>(layout.getIntPtrType(value->getType()));
}

llvm::Value* as_comparison_integer(llvm::IRBuilder<>& builder,
                                   llvm::Value* value,
                                   llvm::IntegerType* integer_type) {
  if (value->getType()->isIntegerTy()) { return value; }
  return builder.CreatePtrToInt(value, integer_type, "obf.zero.ptr");
}

llvm::Value*
create_nonzero(llvm::IRBuilder<>& builder, llvm::Value* delta, llvm::IntegerType* integer_type) {
  llvm::Value* negative = builder.CreateNeg(delta, "obf.zero.neg");
  llvm::Value* folded = builder.CreateOr(delta, negative, "obf.zero.fold");
  llvm::Value* shifted =
      builder.CreateLShr(folded,
                         llvm::ConstantInt::get(integer_type, integer_type->getBitWidth() - 1),
                         "obf.zero.sign");
  return builder.CreateAnd(shifted, llvm::ConstantInt::get(integer_type, 1), "obf.zero.nonzero");
}

llvm::Value*
create_zero_boolean(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs, bool equal) {
  llvm::IntegerType* integer_type = comparison_integer_type(builder, lhs);
  if (integer_type == nullptr || lhs->getType() != rhs->getType()) { return nullptr; }

  llvm::Value* left = as_comparison_integer(builder, lhs, integer_type);
  llvm::Value* right = as_comparison_integer(builder, rhs, integer_type);
  llvm::Value* delta = builder.CreateXor(left, right, "obf.zero.delta");
  llvm::Value* nonzero = create_nonzero(builder, delta, integer_type);
  llvm::Value* result =
      equal ? builder.CreateXor(nonzero, llvm::ConstantInt::get(integer_type, 1), "obf.zero.iszero")
            : nonzero;
  return builder.CreateTrunc(result, builder.getInt1Ty(), "obf.zero.result");
}

bool is_string_comparison_name(llvm::StringRef name) {
  return name == "strcmp" || name == "memcmp" || name == "bcmp" || name == "strncmp";
}

bool is_supported_string_call(const llvm::CallBase& call, const zero_comparison_options& options) {
  if (!options.transform_string_comparisons || call.arg_size() < 2 ||
      !call.getType()->isIntegerTy()) {
    return false;
  }
  const llvm::Function* callee = call.getCalledFunction();
  return callee != nullptr && is_string_comparison_name(callee->getName());
}

const llvm::ConstantDataArray* extract_string_constant(const llvm::Value* value) {
  if (value == nullptr) { return nullptr; }
  const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value->stripPointerCasts());
  if (global == nullptr || !global->hasInitializer()) { return nullptr; }
  const auto* data = llvm::dyn_cast<llvm::ConstantDataArray>(global->getInitializer());
  return (data != nullptr && data->isString()) ? data : nullptr;
}

std::size_t known_compare_length(const llvm::CallBase& call,
                                 llvm::StringRef name,
                                 const zero_comparison_options& options) {
  if (name == "memcmp" || name == "bcmp" || name == "strncmp") {
    if (call.arg_size() < 3) { return 0; }
    const auto* length = llvm::dyn_cast<llvm::ConstantInt>(call.getArgOperand(2));
    if (length == nullptr || length->getZExtValue() > options.max_unroll_bytes) { return 0; }
    return static_cast<std::size_t>(length->getZExtValue());
  }

  const auto* lhs_data = extract_string_constant(call.getArgOperand(0));
  const auto* rhs_data = extract_string_constant(call.getArgOperand(1));
  if (lhs_data != nullptr && rhs_data != nullptr) {
    const std::size_t length = std::min(lhs_data->getNumElements(), rhs_data->getNumElements());
    return length <= options.max_unroll_bytes ? length : 0;
  }
  if (lhs_data != nullptr) {
    return lhs_data->getNumElements() <= options.max_unroll_bytes ? lhs_data->getNumElements() : 0;
  }
  if (rhs_data != nullptr) {
    return rhs_data->getNumElements() <= options.max_unroll_bytes ? rhs_data->getNumElements() : 0;
  }
  return 0;
}

llvm::Value*
create_unrolled_delta(llvm::IRBuilder<>& builder, llvm::CallBase& call, std::size_t length) {
  llvm::Value* delta = llvm::ConstantInt::get(builder.getInt8Ty(), 0);
  llvm::Value* lhs =
      builder.CreateBitCast(call.getArgOperand(0), builder.getPtrTy(), "obf.zero.str.lhs");
  llvm::Value* rhs =
      builder.CreateBitCast(call.getArgOperand(1), builder.getPtrTy(), "obf.zero.str.rhs");
  for (std::size_t index = 0; index < length; ++index) {
    llvm::Value* offset = llvm::ConstantInt::get(builder.getInt64Ty(), index);
    llvm::Value* lhs_byte = builder.CreateLoad(
        builder.getInt8Ty(),
        builder.CreateInBoundsGEP(builder.getInt8Ty(), lhs, offset, "obf.zero.str.lhs.ptr"),
        "obf.zero.str.lhs.byte");
    llvm::Value* rhs_byte = builder.CreateLoad(
        builder.getInt8Ty(),
        builder.CreateInBoundsGEP(builder.getInt8Ty(), rhs, offset, "obf.zero.str.rhs.ptr"),
        "obf.zero.str.rhs.byte");
    delta = builder.CreateOr(
        delta, builder.CreateXor(lhs_byte, rhs_byte, "obf.zero.str.xor"), "obf.zero.str.delta");
  }
  return delta;
}

llvm::Value* replace_string_call(llvm::CallBase& call, const zero_comparison_options& options) {
  llvm::Function* callee = call.getCalledFunction();
  if (callee == nullptr) { return nullptr; }
  const std::size_t length = known_compare_length(call, callee->getName(), options);
  if (length == 0) { return nullptr; }

  llvm::IRBuilder<> builder(&call);
  llvm::Value* delta = create_unrolled_delta(builder, call, length);
  llvm::Type* result_type = call.getType();
  if (result_type->getIntegerBitWidth() > 8) {
    return builder.CreateZExt(delta, result_type, "obf.zero.str.result");
  }
  if (result_type->getIntegerBitWidth() < 8) {
    return builder.CreateTrunc(delta, result_type, "obf.zero.str.result");
  }
  return delta;
}

llvm::Value* replace_select(llvm::SelectInst& select, const zero_comparison_options& options) {
  auto* compare = llvm::dyn_cast<llvm::ICmpInst>(select.getCondition());
  if (compare == nullptr || !is_supported_comparison(*compare) ||
      !select.getType()->isIntegerTy()) {
    return nullptr;
  }
  llvm::IRBuilder<> builder(&select);
  llvm::Value* condition = create_zero_boolean(builder,
                                               compare->getOperand(0),
                                               compare->getOperand(1),
                                               compare->getPredicate() == llvm::ICmpInst::ICMP_EQ);
  if (condition == nullptr) { return nullptr; }
  auto* value_type = llvm::cast<llvm::IntegerType>(select.getType());
  llvm::Value* mask = builder.CreateNeg(
      builder.CreateSExt(condition, value_type, "obf.zero.mask.ext"), "obf.zero.mask");
  llvm::Value* true_arm = builder.CreateAnd(select.getTrueValue(), mask, "obf.zero.select.true");
  llvm::Value* false_arm =
      builder.CreateAnd(select.getFalseValue(), builder.CreateNot(mask), "obf.zero.select.false");
  return builder.CreateOr(true_arm, false_arm, "obf.zero.select");
}

bool is_candidate(const llvm::Instruction& instruction, const zero_comparison_options& options) {
  if (const auto* compare = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
    return options.transform_integer_comparisons && is_supported_comparison(*compare);
  }
  if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
    return is_supported_string_call(*call, options) &&
           known_compare_length(*call, call->getCalledFunction()->getName(), options) != 0;
  }
  if (const auto* select = llvm::dyn_cast<llvm::SelectInst>(&instruction)) {
    const auto* compare = llvm::dyn_cast<llvm::ICmpInst>(select->getCondition());
    return options.transform_integer_comparisons && compare != nullptr &&
           is_supported_comparison(*compare) && select->getType()->isIntegerTy();
  }
  return false;
}

zero_comparison_result analyze_impl(const llvm::Function& function,
                                    const zero_comparison_options& options) {
  if (function.isDeclaration()) { return {.transformed_site_count = 0, .detail = "declaration"}; }
  if (options.max_sites_per_function == 0) {
    return {.transformed_site_count = 0, .detail = "max_sites_per_function is zero"};
  }
  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      if (!is_candidate(instruction, options)) { continue; }
      ++count;
      if (count >= options.max_sites_per_function) {
        return {.transformed_site_count = count,
                .detail = std::to_string(count) + " zero-comparison site(s) available"};
      }
    }
  }
  return {.transformed_site_count = count,
          .detail = count == 0 ? "no eligible comparison sites"
                               : std::to_string(count) + " zero-comparison site(s) available"};
}

}  // namespace

zero_comparison_result analyze_zero_comparison(const llvm::Function& function,
                                               const zero_comparison_options& options) {
  return analyze_impl(function, options);
}

zero_comparison_result run_zero_comparison(llvm::Function& function,
                                           const zero_comparison_options& options) {
  const zero_comparison_result analysis = analyze_impl(function, options);
  if (analysis.transformed_site_count == 0) { return analysis; }

  llvm::SmallVector<llvm::Instruction*, 16> candidates;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      if (is_candidate(instruction, options)) { candidates.push_back(&instruction); }
    }
  }

  std::size_t transformed = 0;
  for (llvm::Instruction* instruction : candidates) {
    if (transformed >= options.max_sites_per_function || instruction == nullptr) { break; }
    llvm::Value* replacement = nullptr;
    if (auto* compare = llvm::dyn_cast<llvm::ICmpInst>(instruction)) {
      llvm::IRBuilder<> builder(compare);
      replacement = create_zero_boolean(builder,
                                        compare->getOperand(0),
                                        compare->getOperand(1),
                                        compare->getPredicate() == llvm::ICmpInst::ICMP_EQ);
    } else if (auto* call = llvm::dyn_cast<llvm::CallBase>(instruction)) {
      replacement = replace_string_call(*call, options);
    } else if (auto* select = llvm::dyn_cast<llvm::SelectInst>(instruction)) {
      replacement = replace_select(*select, options);
    }
    if (replacement == nullptr) { continue; }
    replacement->takeName(instruction);
    instruction->replaceAllUsesWith(replacement);
    instruction->eraseFromParent();
    ++transformed;
  }

  return {.transformed_site_count = transformed,
          .detail = std::to_string(transformed) + " zero-comparison site(s) applied"};
}

}  // namespace obf
