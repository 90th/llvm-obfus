#include "obf/transforms/lifter_destruction.h"

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>

namespace obf {

namespace {

constexpr const char* kTrapAsm =
    "cmpq $0, $1; "
    "jne 1f; "
    ".byte 0x0f; "
    "1:; "
    ".byte 0x1f, 0x44, 0x00, 0x00";

constexpr llvm::StringLiteral kVmHubAttrs[] = {"vm.dispatch.shape.switch",
                                               "vm.handler.route.trampoline",
                                               "vm.island.helper",
                                               "vm.island.subroute"};

struct candidate_site {
  llvm::BasicBlock* block = nullptr;
  std::uint64_t rank = 0;
  std::uint32_t score = 0;
};

bool is_supported_architecture(const llvm::Module& module) {
  const llvm::Triple triple(module.getTargetTriple());
  return triple.isX86() && triple.getArch() == llvm::Triple::x86_64;
}

bool block_has_label_prefix(const llvm::BasicBlock& block, llvm::StringRef prefix) {
  return block.hasName() && block.getName().starts_with(prefix);
}

bool function_has_any_attribute(const llvm::Function& function,
                                llvm::ArrayRef<llvm::StringLiteral> attrs) {
  for (llvm::StringLiteral attr : attrs) {
    if (function.hasFnAttribute(attr)) { return true; }
  }
  return false;
}

bool has_musttail_call(const llvm::BasicBlock& block) {
  for (const llvm::Instruction& instruction : block) {
    const auto* call = llvm::dyn_cast<llvm::CallInst>(&instruction);
    if (call != nullptr && call->isMustTailCall()) { return true; }
  }
  return false;
}

bool has_exception_pad_instruction(const llvm::BasicBlock& block) {
  for (const llvm::Instruction& instruction : block) {
    if (llvm::isa<llvm::CatchPadInst>(instruction) || llvm::isa<llvm::CleanupPadInst>(instruction)) {
      return true;
    }
  }
  return false;
}

bool is_supported_site(const llvm::BasicBlock& block) {
  if (block.isEHPad() || llvm::isa<llvm::CatchSwitchInst>(block.getTerminator()) ||
      llvm::isa<llvm::CleanupReturnInst>(block.getTerminator()) || has_musttail_call(block) ||
      has_exception_pad_instruction(block)) {
    return false;
  }

  const llvm::Instruction* terminator = block.getTerminator();
  return terminator != nullptr && !llvm::isa<llvm::UnreachableInst>(terminator) &&
         !llvm::isa<llvm::InvokeInst>(terminator);
}

bool is_vm_dispatch_candidate(const llvm::Function& function,
                              const llvm::BasicBlock& block,
                              const lifter_destruction_options& options) {
  if (!options.target_vm_dispatchers) { return false; }
  if (function_has_any_attribute(function, kVmHubAttrs)) { return true; }
  return block_has_label_prefix(block, "vm.island.route") ||
         block_has_label_prefix(block, "vm.island.root.route") ||
         block_has_label_prefix(block, "vm.island.subroute") ||
         block_has_label_prefix(block, "vm.island.call");
}

bool is_flattened_header_candidate(const llvm::Function& function,
                                   const llvm::BasicBlock& block,
                                   const lifter_destruction_options& options) {
  if (!options.target_flattened_headers) { return false; }
  const auto* terminator = block.getTerminator();
  if (terminator == nullptr) { return false; }
  return function.hasFnAttribute("flatten.dispatch") ||
         &block == &function.getEntryBlock() || llvm::isa<llvm::SwitchInst>(terminator) ||
         terminator->getNumSuccessors() > 1;
}

std::uint32_t score_candidate_block(const llvm::Function& function,
                                    const llvm::BasicBlock& block,
                                    const lifter_destruction_options& options) {
  std::uint32_t score = 0;
  if (is_vm_dispatch_candidate(function, block, options)) { score += 100; }
  if (is_flattened_header_candidate(function, block, options)) { score += 50; }
  if (&block == &function.getEntryBlock()) { score += 20; }
  const llvm::Instruction* terminator = block.getTerminator();
  if (terminator != nullptr) { score += static_cast<std::uint32_t>(terminator->getNumSuccessors() * 5); }
  return score;
}

llvm::SmallVector<candidate_site, 8> collect_candidate_sites(llvm::Function& function,
                                                             const lifter_destruction_options& options,
                                                             std::uint64_t seed) {
  llvm::SmallVector<candidate_site, 8> sites;
  for (llvm::BasicBlock& block : function) {
    if (!is_supported_site(block)) { continue; }
    const std::uint32_t score = score_candidate_block(function, block, options);
    if (score == 0) { continue; }

    std::uint64_t rank = mix_seed(seed, static_cast<std::uint64_t>(score));
    rank = mix_seed(rank, stable_hash_string(function.getName()));
    rank = mix_seed(rank, stable_hash_string(block.hasName() ? block.getName() : llvm::StringRef("")));
    rank = mix_seed(rank, static_cast<std::uint64_t>(block.size() + 1));
    sites.push_back({.block = &block, .rank = rank, .score = score});
  }

  std::sort(sites.begin(), sites.end(), [](const candidate_site& lhs, const candidate_site& rhs) {
    if (lhs.score != rhs.score) { return lhs.score > rhs.score; }
    if (lhs.rank != rhs.rank) { return lhs.rank < rhs.rank; }
    return lhs.block->getName() < rhs.block->getName();
  });
  return sites;
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

  llvm::Function& mutable_function = const_cast<llvm::Function&>(function);
  const llvm::SmallVector<candidate_site, 8> sites =
      collect_candidate_sites(mutable_function, options, stable_hash_string(function.getName()));
  const std::size_t count = sites.size();

  if (count == 0) { return {.insertion_count = 0, .detail = "no eligible basic blocks"}; }
  return {.insertion_count = count,
          .detail = std::to_string(count) + " lifter destruction site(s) available"};
}

llvm::Instruction* find_insertion_point(llvm::BasicBlock& block) {
  for (llvm::Instruction& instruction : block) {
    if (!llvm::isa<llvm::PHINode>(instruction)) {
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

  const llvm::SmallVector<candidate_site, 8> sites = collect_candidate_sites(function, options, seed);
  std::size_t inserted = 0;
  for (const candidate_site& site : sites) {
    if (inserted >= options.max_sites_per_function || site.block == nullptr) { continue; }

    llvm::Instruction* insertion_point = find_insertion_point(*site.block);
    if (insertion_point == nullptr) { continue; }

    llvm::IRBuilder<> builder(insertion_point);
    llvm::Value* true_predicate = mba::build_entropy_true_predicate(builder,
                                                                    function,
                                                                    options.mba_depth,
                                                                    seed ^ site.rank,
                                                                    0x18d3f5a7ULL,
                                                                    0x7b2c491eULL,
                                                                    "obf.lifter.a",
                                                                    "obf.lifter.b",
                                                                    "obf.lifter.true");
    if (true_predicate == nullptr) { continue; }

    llvm::Value* lhs = builder.CreateZExt(true_predicate, i64, "obf.lifter.cmp.lhs");
    mba::builder_context rhs_context =
        mba::get_or_create_builder_context(function, "lifter.rhs", seed ^ (site.rank + 0x41));
    rhs_context.depth = options.mba_depth;
    llvm::Value* rhs_zero = mba::create_opaque_integer(builder,
                                                       i64,
                                                       rhs_context,
                                                       llvm::APInt(64, 0),
                                                       seed ^ (site.rank + 0x91),
                                                       "obf.lifter.cmp.zero");
    llvm::Value* rhs = mba::create_add(builder,
                                       lhs,
                                       rhs_zero,
                                       rhs_context,
                                       seed ^ (site.rank + 0xd1),
                                       "obf.lifter.cmp.rhs");
    builder.CreateCall(trap, {lhs, rhs});
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = inserted == 0 ? "no lifter destruction sites inserted"
                                  : std::to_string(inserted) + " lifter destruction site(s) inserted"};
}

}  // namespace obf
