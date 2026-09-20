#include "obf/transforms/zero_comparison.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include <optional>
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

bool all_users_are_zero_equality(const llvm::CallBase& call) {
  if (call.use_empty()) { return false; }
  for (const llvm::User* user : call.users()) {
    const auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(user);
    if (icmp == nullptr || !is_equality_icmp(*icmp)) { return false; }
    const auto* const_int1 = llvm::dyn_cast<llvm::ConstantInt>(icmp->getOperand(1));
    if (const_int1 != nullptr && const_int1->isZero()) { continue; }
    const auto* const_int0 = llvm::dyn_cast<llvm::ConstantInt>(icmp->getOperand(0));
    if (const_int0 != nullptr && const_int0->isZero()) { continue; }
    return false;
  }
  return true;
}

bool is_supported_string_call(const llvm::CallBase& call, const zero_comparison_options& options) {
  if (!options.transform_string_comparisons || !llvm::isa<llvm::CallInst>(call) ||
      call.arg_size() < 2 || !call.getArgOperand(0)->getType()->isPointerTy() ||
      !call.getArgOperand(1)->getType()->isPointerTy() || !call.getType()->isIntegerTy(32)) {
    return false;
  }
  if (call.getNumOperandBundles() != 0 || llvm::cast<llvm::CallInst>(call).isMustTailCall()) {
    return false;
  }
  const llvm::Function* callee = call.getCalledFunction();
  if (callee == nullptr || !callee->isDeclaration() || callee->isIntrinsic()) {
    return false;
  }
  if (!is_string_comparison_name(callee->getName()) ||
      call.arg_size() != (callee->getName() == "strcmp" ? 2u : 3u)) {
    return false;
  }
  if (callee->getName() != "bcmp" && !all_users_are_zero_equality(call)) {
    return false;
  }
  return true;
}

const llvm::ConstantDataArray* extract_string_constant(const llvm::Value* value) {
  if (value == nullptr) { return nullptr; }
  const auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value->stripPointerCasts());
  if (global == nullptr || !global->isConstant() || !global->hasDefinitiveInitializer()) {
    return nullptr;
  }
  const auto* data = llvm::dyn_cast<llvm::ConstantDataArray>(global->getInitializer());
  return (data != nullptr && data->isString()) ? data : nullptr;
}
std::optional<std::size_t> c_string_length(const llvm::ConstantDataArray* data) {
  if (data == nullptr) { return std::nullopt; }
  for (unsigned i = 0; i < data->getNumElements(); ++i) {
    if (data->getElementAsInteger(i) == 0) {
      return i + 1;
    }
  }
  return std::nullopt;
}

std::optional<std::size_t> known_compare_length(const llvm::CallBase& call,
                                                llvm::StringRef name,
                                                const zero_comparison_options& options) {
  if (name == "memcmp" || name == "bcmp" || name == "strncmp") {
    if (call.arg_size() < 3) { return std::nullopt; }
    const auto* length = llvm::dyn_cast<llvm::ConstantInt>(call.getArgOperand(2));
    if (length == nullptr || length->getValue().getActiveBits() > 64 ||
        length->getZExtValue() > options.max_unroll_bytes ||
        (length->isZero() && name != "strncmp")) {
      return std::nullopt;
    }
    return static_cast<std::size_t>(length->getZExtValue());
  }

  const auto lhs_length = c_string_length(extract_string_constant(call.getArgOperand(0)));
  const auto rhs_length = c_string_length(extract_string_constant(call.getArgOperand(1)));
  const auto length = lhs_length && rhs_length ? std::min(*lhs_length, *rhs_length)
                      : lhs_length             ? lhs_length
                                               : rhs_length;
  return length && *length <= options.max_unroll_bytes ? length : std::nullopt;
}

llvm::Value*
create_unrolled_delta(llvm::IRBuilder<>& builder, llvm::CallBase& call, std::size_t length) {
  llvm::Value* delta = llvm::ConstantInt::get(builder.getInt8Ty(), 0);
  llvm::Value* lhs = call.getArgOperand(0);
  llvm::Value* rhs = call.getArgOperand(1);
  for (std::size_t index = 0; index < length; ++index) {
    llvm::Value* offset = llvm::ConstantInt::get(builder.getInt64Ty(), index);
    llvm::Value* lhs_byte = builder.CreateAlignedLoad(
        builder.getInt8Ty(),
        builder.CreateGEP(builder.getInt8Ty(), lhs, offset, "obf.zero.str.lhs.ptr"),
        llvm::Align(1),
        "obf.zero.str.lhs.byte");
    llvm::Value* rhs_byte = builder.CreateAlignedLoad(
        builder.getInt8Ty(),
        builder.CreateGEP(builder.getInt8Ty(), rhs, offset, "obf.zero.str.rhs.ptr"),
        llvm::Align(1),
        "obf.zero.str.rhs.byte");
    delta = builder.CreateOr(
        delta, builder.CreateXor(lhs_byte, rhs_byte, "obf.zero.str.xor"), "obf.zero.str.delta");
  }
  return delta;
}

llvm::Value*
create_short_circuit_delta(llvm::IRBuilder<>& builder, llvm::CallBase& call, std::size_t length) {
  if (length == 0) { return builder.getInt8(0); }

  llvm::BasicBlock* block = call.getParent();
  llvm::BasicBlock* continuation = block->splitBasicBlock(call.getIterator(), "obf.zero.str.end");
  block->getTerminator()->eraseFromParent();
  builder.SetInsertPoint(&call);
  auto* result = builder.CreatePHI(builder.getInt8Ty(), length, "obf.zero.str.delta");
  builder.SetInsertPoint(block);
  for (std::size_t index = 0; index < length; ++index) {
    llvm::Value* offset = builder.getInt64(index);
    llvm::Value* lhs = builder.CreateAlignedLoad(
        builder.getInt8Ty(),
        builder.CreateGEP(builder.getInt8Ty(), call.getArgOperand(0), offset),
        llvm::Align(1),
        "obf.zero.str.lhs.byte");
    llvm::Value* rhs = builder.CreateAlignedLoad(
        builder.getInt8Ty(),
        builder.CreateGEP(builder.getInt8Ty(), call.getArgOperand(1), offset),
        llvm::Align(1),
        "obf.zero.str.rhs.byte");
    llvm::Value* delta = builder.CreateXor(lhs, rhs, "obf.zero.str.xor");
    result->addIncoming(delta, builder.GetInsertBlock());
    if (index + 1 == length) {
      builder.CreateBr(continuation);
      break;
    }

    // A later byte is accessible only while both strings continue and still match.
    llvm::Value* more = builder.CreateAnd(builder.CreateICmpEQ(delta, builder.getInt8(0)),
                                          builder.CreateICmpNE(lhs, builder.getInt8(0)));
    auto* next = llvm::BasicBlock::Create(
        call.getContext(), "obf.zero.str.next", block->getParent(), continuation);
    builder.CreateCondBr(more, next, continuation);
    builder.SetInsertPoint(next);
  }
  builder.SetInsertPoint(&call);
  return result;
}

llvm::Value* replace_string_call(llvm::CallBase& call, const zero_comparison_options& options) {
  llvm::Function* callee = call.getCalledFunction();
  if (callee == nullptr) { return nullptr; }
  const auto length = known_compare_length(call, callee->getName(), options);
  if (!length) { return nullptr; }

  llvm::IRBuilder<> builder(&call);
  const bool is_string = callee->getName() == "strcmp" || callee->getName() == "strncmp";
  llvm::Value* delta = is_string ? create_short_circuit_delta(builder, call, *length)
                                 : create_unrolled_delta(builder, call, *length);
  return builder.CreateZExt(delta, call.getType(), "obf.zero.str.result");
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
  llvm::Value* mask = builder.CreateSExt(condition, value_type, "obf.zero.mask");
  // Unlike select, bitwise masking propagates poison from either arm.
  llvm::Value* true_value = builder.CreateFreeze(select.getTrueValue(), "obf.zero.true");
  llvm::Value* false_value = builder.CreateFreeze(select.getFalseValue(), "obf.zero.false");
  llvm::Value* true_arm = builder.CreateAnd(true_value, mask, "obf.zero.select.true");
  llvm::Value* false_arm =
      builder.CreateAnd(false_value, builder.CreateNot(mask), "obf.zero.select.false");
  return builder.CreateOr(true_arm, false_arm, "obf.zero.select");
}

bool is_candidate(const llvm::Instruction& instruction, const zero_comparison_options& options) {
  if (const auto* compare = llvm::dyn_cast<llvm::ICmpInst>(&instruction)) {
    return options.transform_integer_comparisons && is_supported_comparison(*compare);
  }
  if (const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
    return is_supported_string_call(*call, options) &&
           known_compare_length(*call, call->getCalledFunction()->getName(), options).has_value();
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
