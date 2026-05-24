#include "obf/transforms/lifter_destruction.h"

#include "obf/transforms/mba.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/TargetParser/Triple.h"

#include <cstdint>

namespace obf {

namespace {

constexpr const char* kTrapAsm =
    "cmpq $0, $1; "
    "jne 1f; "
    ".byte 0x0f; "
    "1:; "
    ".byte 0x1f, 0x44, 0x00, 0x00";

bool is_supported_architecture(const llvm::Module& module) {
  const llvm::Triple triple(module.getTargetTriple());
  return triple.isX86() && triple.getArch() == llvm::Triple::x86_64;
}

bool is_supported_site(const llvm::BasicBlock& block) {
  if (block.isEHPad()) { return false; }
  const llvm::Instruction* terminator = block.getTerminator();
  return terminator != nullptr && !llvm::isa<llvm::UnreachableInst>(terminator) &&
         !llvm::isa<llvm::InvokeInst>(terminator);
}

lifter_destruction_result analyze_impl(const llvm::Function& function,
                                       const lifter_destruction_options& options) {
  if (function.isDeclaration()) { return {.insertion_count = 0, .detail = "declaration"}; }
  if (!options.enabled) { return {.insertion_count = 0, .detail = "disabled"}; }
  if (options.max_sites_per_function == 0) {
    return {.insertion_count = 0, .detail = "max_sites_per_function is zero"};
  }

  const llvm::Module* module = function.getParent();
  if (module == nullptr || !is_supported_architecture(*module)) {
    return {.insertion_count = 0, .detail = "skipped_unsupported_arch"};
  }

  std::size_t count = 0;
  for (const llvm::BasicBlock& block : function) {
    if (!is_supported_site(block)) { continue; }
    ++count;
    if (count >= options.max_sites_per_function) {
      return {.insertion_count = count,
              .detail = std::to_string(count) + " lifter destruction site(s) available"};
    }
  }

  if (count == 0) { return {.insertion_count = 0, .detail = "no eligible basic blocks"}; }
  return {.insertion_count = count,
          .detail = std::to_string(count) + " lifter destruction site(s) available"};
}

llvm::Instruction* find_insertion_point(llvm::BasicBlock& block) {
  for (llvm::Instruction& instruction : block) {
    if (!llvm::isa<llvm::PHINode>(instruction) && !llvm::isa<llvm::AllocaInst>(instruction)) {
      return &instruction;
    }
  }
  return block.getTerminator();
}

}  // namespace

lifter_destruction_result analyze_lifter_destruction(const llvm::Function& function,
                                                     const lifter_destruction_options& options) {
  return analyze_impl(function, options);
}

lifter_destruction_result run_lifter_destruction(llvm::Function& function,
                                                 const lifter_destruction_options& options,
                                                 std::uint64_t seed) {
  const lifter_destruction_result analysis = analyze_impl(function, options);
  if (analysis.insertion_count == 0) { return analysis; }

  llvm::Module* module = function.getParent();
  if (module == nullptr) { return {.insertion_count = 0, .detail = "missing parent module"}; }

  llvm::LLVMContext& context = function.getContext();
  llvm::IntegerType* i64 = llvm::Type::getInt64Ty(context);
  llvm::FunctionType* asm_type = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i64, i64}, false);
  llvm::InlineAsm* trap = llvm::InlineAsm::get(
      asm_type, kTrapAsm, "r,r,~{cc},~{memory}", true, false, llvm::InlineAsm::AD_ATT);

  std::size_t inserted = 0;
  for (llvm::BasicBlock& block : function) {
    if (inserted >= options.max_sites_per_function || !is_supported_site(block)) { continue; }

    llvm::Instruction* insertion_point = find_insertion_point(block);
    if (insertion_point == nullptr) { continue; }

    llvm::IRBuilder<> builder(insertion_point);
    llvm::Value* true_predicate = mba::build_entropy_true_predicate(builder,
                                                                    function,
                                                                    options.mba_depth,
                                                                    seed ^ (inserted + 1),
                                                                    0x18d3f5a7ULL,
                                                                    0x7b2c491eULL,
                                                                    "obf.lifter.a",
                                                                    "obf.lifter.b",
                                                                    "obf.lifter.true");
    if (true_predicate == nullptr) { continue; }

    llvm::Value* lhs = builder.CreateZExt(true_predicate, i64, "obf.lifter.cmp.lhs");
    mba::builder_context rhs_context =
        mba::get_or_create_builder_context(function, "lifter.rhs", seed ^ (inserted + 0x41));
    rhs_context.depth = options.mba_depth;
    llvm::Value* rhs_zero = mba::create_opaque_integer(builder,
                                                       i64,
                                                       rhs_context,
                                                       llvm::APInt(64, 0),
                                                       seed ^ (inserted + 0x91),
                                                       "obf.lifter.cmp.zero");
    llvm::Value* rhs = mba::create_add(builder,
                                       lhs,
                                       rhs_zero,
                                       rhs_context,
                                       seed ^ (inserted + 0xd1),
                                       "obf.lifter.cmp.rhs");
    builder.CreateCall(trap, {lhs, rhs});
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = inserted == 0 ? "no lifter destruction sites inserted"
                                  : std::to_string(inserted) + " lifter destruction site(s) inserted"};
}

}  // namespace obf
