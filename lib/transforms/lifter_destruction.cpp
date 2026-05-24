#include "obf/transforms/lifter_destruction.h"

#include "obf/support/stable_hash.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/CodeGen.h"
#include "llvm/TargetParser/Triple.h"

#include <algorithm>
#include <cstdint>

namespace obf {

namespace {

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

bool supports_elf_eh_spoofing(const llvm::Module& module) {
  return llvm::Triple(module.getTargetTriple()).isOSBinFormatELF();
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

bool function_has_existing_exception_handling(const llvm::Function& function) {
  if (function.hasPersonalityFn()) { return true; }

  for (const llvm::BasicBlock& block : function) {
    if (block.isEHPad()) { return true; }

    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::InvokeInst>(instruction) || llvm::isa<llvm::LandingPadInst>(instruction) ||
          llvm::isa<llvm::CatchSwitchInst>(instruction) || llvm::isa<llvm::CatchPadInst>(instruction) ||
          llvm::isa<llvm::CleanupPadInst>(instruction) || llvm::isa<llvm::CatchReturnInst>(instruction) ||
          llvm::isa<llvm::CleanupReturnInst>(instruction) || llvm::isa<llvm::ResumeInst>(instruction)) {
        return true;
      }
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

std::string build_label_name(llvm::StringRef prefix, llvm::StringRef suffix) {
  std::string name;
  name.reserve(prefix.size() + suffix.size());
  name += prefix;
  name += suffix;
  return name;
}

std::string build_site_label_prefix(const llvm::Function& function,
                                    const candidate_site& site,
                                    std::uint64_t seed,
                                    std::size_t ordinal) {
  const llvm::StringRef block_name = site.block != nullptr && site.block->hasName()
                                         ? site.block->getName()
                                         : llvm::StringRef("bb");
  std::uint64_t unique_id = mix_seed(seed, site.rank);
  unique_id = mix_seed(unique_id, stable_hash_string(block_name));
  unique_id = mix_seed(unique_id, static_cast<std::uint64_t>(ordinal + 1));
  return ".Lobf_ld_" + llvm::utohexstr(stable_hash_string(function.getName(), unique_id));
}

std::string build_trampoline_asm(const llvm::Function& function,
                                 const candidate_site& site,
                                 std::uint64_t seed,
                                 std::size_t ordinal,
                                 bool emit_elf_eh_spoofing) {
  const std::string prefix = build_site_label_prefix(function, site, seed, ordinal);
  const std::string site_begin = build_label_name(prefix, "_site_begin");
  const std::string retaddr = build_label_name(prefix, "_retaddr");
  const std::string poison = build_label_name(prefix, "_poison");
  const std::string poison_mid = build_label_name(prefix, "_poison_mid");
  const std::string resume = build_label_name(prefix, "_resume");

  std::string assembly;
  assembly.reserve(768);
  assembly += site_begin;
  assembly += ":; ";
  assembly += "call ";
  assembly += retaddr;
  assembly += "; ";
  assembly += retaddr;
  assembly += ":; popq %rax; movl $$(";
  assembly += resume;
  assembly += '-';
  assembly += retaddr;
  assembly += "), %ecx; addq %rcx, %rax; jmpq *%rax; ";
  assembly += poison;
  assembly += ":; .byte 0x0f, 0x85; ";
  assembly += poison_mid;
  assembly += ":; .byte 0xff, 0xe0, 0x0f, 0x0b; ";
  assembly += resume;
  assembly += ':';

  if (!emit_elf_eh_spoofing) { return assembly; }

  const std::string lsda = build_label_name(prefix, "_lsda");
  const std::string callsite_begin = build_label_name(prefix, "_cst_begin");
  const std::string callsite_end = build_label_name(prefix, "_cst_end");
  assembly += "; .cfi_lsda 0x1b, ";
  assembly += lsda;
  assembly += "; .pushsection .gcc_except_table,\"a\",@progbits; ";
  assembly += lsda;
  assembly += ":; .byte 0x1b; .long ";
  assembly += site_begin;
  assembly += "-.; .byte 0xff; .byte 0x01; .uleb128 ";
  assembly += callsite_end;
  assembly += '-';
  assembly += callsite_begin;
  assembly += "; ";
  assembly += callsite_begin;
  assembly += ":; .uleb128 0; .uleb128 ";
  assembly += resume;
  assembly += '-';
  assembly += site_begin;
  assembly += "; .uleb128 ";
  assembly += poison_mid;
  assembly += '-';
  assembly += site_begin;
  assembly += "; .uleb128 0; ";
  assembly += callsite_end;
  assembly += ":; .popsection";
  return assembly;
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

  const bool allow_elf_eh_spoofing =
      supports_elf_eh_spoofing(*module) && !function_has_existing_exception_handling(function);

  const llvm::SmallVector<candidate_site, 8> sites = collect_candidate_sites(function, options, seed);
  std::size_t inserted = 0;
  bool emitted_eh_spoofing = false;
  for (std::size_t site_index = 0; site_index < sites.size(); ++site_index) {
    const candidate_site& site = sites[site_index];
    if (inserted >= options.max_sites_per_function || site.block == nullptr) { continue; }

    llvm::Instruction* insertion_point = find_insertion_point(*site.block);
    if (insertion_point == nullptr) { continue; }

    const bool emit_elf_eh_spoofing = allow_elf_eh_spoofing && !emitted_eh_spoofing;
    if (emit_elf_eh_spoofing && !function.hasUWTable()) {
      function.setUWTableKind(llvm::UWTableKind::Default);
    }

    llvm::FunctionType* asm_type =
        llvm::FunctionType::get(llvm::Type::getVoidTy(function.getContext()), false);
    llvm::InlineAsm* trap = llvm::InlineAsm::get(
        asm_type,
        build_trampoline_asm(function, site, seed, site_index, emit_elf_eh_spoofing),
        "~{rax},~{rcx},~{cc},~{memory}",
        true,
        false,
        llvm::InlineAsm::AD_ATT);
    llvm::CallInst::Create(trap, {}, "", insertion_point->getIterator());
    emitted_eh_spoofing |= emit_elf_eh_spoofing;
    ++inserted;
  }

  return {.insertion_count = inserted,
          .detail = inserted == 0 ? "no lifter destruction sites inserted"
                                  : std::to_string(inserted) + " lifter destruction site(s) inserted"};
}

}  // namespace obf
