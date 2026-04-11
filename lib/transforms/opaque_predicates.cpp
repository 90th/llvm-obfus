#include "obf/transforms/opaque_predicates.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

namespace obf {

namespace {

llvm::Value *find_seed_value(llvm::Function &function) {
  for (llvm::Argument &argument : function.args()) {
    if (argument.getType()->isIntegerTy() || argument.getType()->isPointerTy()) {
      return &argument;
    }
  }

  return nullptr;
}

opaque_predicate_result analyze_impl(const llvm::Function &function,
                                     const opaque_predicate_options &options) {
  if (function.isDeclaration()) {
    return {.insertion_count = 0, .detail = "declaration"};
  }

  if (options.max_insertions_per_function == 0) {
    return {.insertion_count = 0, .detail = "max_insertions_per_function is zero"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock &block : function) {
    const auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) {
      continue;
    }

    ++count;
    if (count >= options.max_insertions_per_function) {
      return {.insertion_count = count,
              .detail = std::to_string(count) + " opaque predicate site(s) available"};
    }
  }

  if (count == 0) {
    return {.insertion_count = 0, .detail = "no conditional branches"};
  }

  return {.insertion_count = count,
          .detail = std::to_string(count) + " opaque predicate site(s) available"};
}

} // namespace

opaque_predicate_result
analyze_opaque_predicates(const llvm::Function &function,
                          const opaque_predicate_options &options) {
  return analyze_impl(function, options);
}

opaque_predicate_result
run_opaque_predicates(llvm::Function &function,
                      const opaque_predicate_options &options) {
  const opaque_predicate_result analysis = analyze_impl(function, options);
  if (analysis.insertion_count == 0) {
    return analysis;
  }

  llvm::Value *seed_value = find_seed_value(function);
  if (seed_value == nullptr) {
    return {.insertion_count = 0, .detail = "no suitable opaque seed value"};
  }

  std::size_t inserted = 0;
  for (llvm::BasicBlock &block : function) {
    if (inserted >= options.max_insertions_per_function) {
      break;
    }

    auto *branch = llvm::dyn_cast<llvm::BranchInst>(block.getTerminator());
    if (branch == nullptr || !branch->isConditional()) {
      continue;
    }

    llvm::IRBuilder<> builder(branch);
    llvm::Value *opaque = seed_value;
    if (opaque->getType()->isPointerTy()) {
      opaque = builder.CreatePtrToInt(
          opaque, llvm::Type::getInt64Ty(function.getContext()), "obf.ptrseed");
    }

    llvm::Value *minus_one = builder.CreateSub(
        opaque, llvm::ConstantInt::get(opaque->getType(), 1), "obf.opaque.dec");
    llvm::Value *product = builder.CreateMul(opaque, minus_one, "obf.opaque.mul");
    llvm::Value *masked = builder.CreateAnd(
        product, llvm::ConstantInt::get(opaque->getType(), 1), "obf.opaque.and");
    llvm::Value *predicate = builder.CreateICmpEQ(
        masked, llvm::ConstantInt::get(masked->getType(), 0), "obf.opaque.true");
    llvm::Value *new_cond = builder.CreateAnd(branch->getCondition(), predicate,
                                              "obf.opaque.cond");
    branch->setCondition(new_cond);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) + " opaque predicate(s) inserted"};
}

} // namespace obf
