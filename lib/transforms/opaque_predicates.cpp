#include "obf/transforms/opaque_predicates.h"

#include "obf/transforms/mba.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>

namespace obf {

namespace {

constexpr llvm::StringRef kCfgStatePlaceholderName = "__obf_get_cfg_state";
constexpr llvm::StringRef kExpectedCfgStatePlaceholderName =
    "__obf_get_expected_cfg_state";

llvm::Value *build_entropy_mba_predicate(llvm::IRBuilder<> &builder,
                                         llvm::Function &function,
                                         const opaque_predicate_options &options,
                                         std::uint64_t salt_base) {
  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  auto *anchor = mba::get_or_create_entropy_anchor(*module);
  llvm::Value *entropy =
      builder.CreateLoad(builder.getInt64Ty(), anchor, "obf.opaque.entropy");

  mba::builder_context context_a =
      mba::get_or_create_builder_context(function, "obf.opaque.a",
                                         salt_base ^ 0x13579bdfULL);
  mba::builder_context context_b =
      mba::get_or_create_builder_context(function, "obf.opaque.b",
                                         salt_base ^ 0x2468ace0ULL);
  context_a.depth = options.mba_depth;
  context_b.depth = options.mba_depth;

  llvm::Value *seed_a = mba::entangle_value(
      builder, entropy, context_a, salt_base + 0x11ULL, "obf.opaque.seed.a");
  llvm::Value *zero_a = mba::create_opaque_integer(
      builder, builder.getInt64Ty(), context_a, llvm::APInt(64, 0),
      salt_base + 0x21ULL, "obf.opaque.zero.a");
  llvm::Value *expr_a = mba::create_add(builder, seed_a, zero_a, context_a,
                                        salt_base + 0x31ULL,
                                        "obf.opaque.expr.a");

  llvm::Value *seed_b = mba::entangle_value(
      builder, entropy, context_b, salt_base + 0x41ULL, "obf.opaque.seed.b");
  llvm::Value *zero_b = mba::create_opaque_integer(
      builder, builder.getInt64Ty(), context_b, llvm::APInt(64, 0),
      salt_base + 0x51ULL, "obf.opaque.zero.b");
  llvm::Value *expr_b = mba::create_xor(builder, seed_b, zero_b, context_b,
                                        salt_base + 0x61ULL,
                                        "obf.opaque.expr.b");

  return builder.CreateICmpEQ(expr_a, expr_b, "obf.opaque.true");
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
              .detail = std::to_string(count) +
                        " opaque predicate site(s) available"};
    }
  }

  if (count == 0) {
    return {.insertion_count = 0, .detail = "no conditional branches"};
  }

  return {.insertion_count = count,
          .detail = std::to_string(count) +
                    " opaque predicate site(s) available"};
}

bool cleanup_cfg_state_placeholder(llvm::Module &module, llvm::StringRef name) {
  llvm::Function *placeholder = module.getFunction(name);
  if (placeholder == nullptr) {
    return false;
  }

  llvm::SmallVector<llvm::CallBase *, 8> calls;
  for (llvm::User *user : placeholder->users()) {
    if (auto *call = llvm::dyn_cast<llvm::CallBase>(user)) {
      calls.push_back(call);
    }
  }

  for (llvm::CallBase *call : calls) {
    if (call == nullptr) {
      continue;
    }

    call->replaceAllUsesWith(llvm::Constant::getNullValue(call->getType()));
    call->eraseFromParent();
  }

  const bool changed = !calls.empty();
  if (placeholder->use_empty() && placeholder->isDeclaration()) {
    placeholder->eraseFromParent();
  }

  return changed;
}

} // namespace

bool RunCfgStateCleanup(llvm::Module &module) {
  bool changed = false;
  changed |= cleanup_cfg_state_placeholder(module, kCfgStatePlaceholderName);
  changed |= cleanup_cfg_state_placeholder(module, kExpectedCfgStatePlaceholderName);
  return changed;
}

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
    llvm::Value *predicate = build_entropy_mba_predicate(
        builder, function, options, static_cast<std::uint64_t>(inserted + 1));
    if (predicate == nullptr) {
      continue;
    }

    llvm::Value *new_cond = builder.CreateAnd(branch->getCondition(), predicate,
                                              "obf.opaque.cond");
    branch->setCondition(new_cond);
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = std::to_string(inserted) +
                    " opaque predicate(s) inserted"};
}

} // namespace obf
