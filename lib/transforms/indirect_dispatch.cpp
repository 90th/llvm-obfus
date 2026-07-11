#include "obf/transforms/indirect_dispatch.h"

#include "obf/support/affine_helpers.h"
#include "obf/support/ir_name.h"
#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"

#include "llvm/ADT/APInt.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

namespace obf {

namespace {

enum class dispatch_site_kind {
  branch,
  switch_dispatch,
};

struct dispatch_site {
  dispatch_site_kind kind = dispatch_site_kind::branch;
  llvm::Instruction* terminator = nullptr;
  llvm::SmallVector<llvm::BasicBlock*, 8> unique_targets;
  llvm::BasicBlock* default_target = nullptr;
  std::uint64_t seed = 0;
};

struct site_collection {
  llvm::SmallVector<dispatch_site, 8> sites;
  std::string detail;
  std::size_t selected_branch_sites = 0;
  std::size_t selected_switch_sites = 0;
  std::size_t skipped_max_switch_targets = 0;
  std::size_t first_oversized_switch_targets = 0;
  std::size_t max_switch_targets_limit = 0;
  std::size_t blocked_non_integral_program_address_space = 0;
  std::size_t blocked_unsupported_function_shape = 0;
};

struct site_masking {
  llvm::IntegerType* int_type = nullptr;
  llvm::Type* pointer_type = nullptr;
  llvm::ConstantInt* key_constant = nullptr;
  llvm::ConstantInt* bias_constant = nullptr;
  llvm::ConstantInt* affine_multiplier_constant = nullptr;
  llvm::ConstantInt* affine_bias_constant = nullptr;
  llvm::ConstantInt* affine_inverse_constant = nullptr;
  bool use_affine_delta = false;
  unsigned rotate_amount = 0;
  llvm::DenseMap<llvm::BasicBlock*, llvm::Value*> encoded_tokens;
};

site_collection make_empty_site_collection(std::string detail) {
  return {.sites = {}, .detail = std::move(detail)};
}

llvm::StringRef selected_site_shape(std::size_t branch_sites, std::size_t switch_sites) {
  if (branch_sites != 0 && switch_sites == 0) { return "branch_only"; }
  if (branch_sites == 0 && switch_sites != 0) { return "switch_only"; }
  if (branch_sites != 0 && switch_sites != 0) { return "mixed"; }
  return "none";
}

void append_selection_summary(std::string& detail, const site_collection& collection) {
  detail += "; selected(branch_sites=";
  detail += std::to_string(collection.selected_branch_sites);
  detail += ", switch_sites=";
  detail += std::to_string(collection.selected_switch_sites);
  detail += ", shape=";
  detail +=
      selected_site_shape(collection.selected_branch_sites, collection.selected_switch_sites).str();
  detail += ")";
}

std::string make_result_detail(const indirect_dispatch_result& result, llvm::StringRef suffix) {
  std::string detail = std::to_string(result.site_count) +
                       " site(s) rewritten (branches=" + std::to_string(result.branch_site_count) +
                       ", switches=" + std::to_string(result.switch_site_count) + "); " +
                       suffix.str();
  detail += "; selected(branch_sites=";
  detail += std::to_string(result.branch_site_count);
  detail += ", switch_sites=";
  detail += std::to_string(result.switch_site_count);
  detail += ", shape=";
  detail += selected_site_shape(result.branch_site_count, result.switch_site_count).str();
  detail += ")";
  if (result.skipped_max_switch_targets != 0 ||
      result.blocked_non_integral_program_address_space != 0 ||
      result.blocked_unsupported_function_shape != 0) {
    detail += "; skipped(max_switch_targets=";
    detail += std::to_string(result.skipped_max_switch_targets);
    detail += ", non_integral_program_as=";
    detail += std::to_string(result.blocked_non_integral_program_address_space);
    detail += ", unsupported_function_shape=";
    detail += std::to_string(result.blocked_unsupported_function_shape);
    detail += ")";
  }
  if (result.first_oversized_switch_targets != 0 && result.max_switch_targets_limit != 0) {
    detail += "; first_oversized_switch_targets=";
    detail += std::to_string(result.first_oversized_switch_targets);
    detail += ">";
    detail += std::to_string(result.max_switch_targets_limit);
  }
  return detail;
}

void append_skip_summary(std::string& detail, const site_collection& collection) {
  if (collection.skipped_max_switch_targets == 0 &&
      collection.blocked_non_integral_program_address_space == 0 &&
      collection.blocked_unsupported_function_shape == 0) {
    return;
  }

  detail += "; skipped(max_switch_targets=";
  detail += std::to_string(collection.skipped_max_switch_targets);
  detail += ", non_integral_program_as=";
  detail += std::to_string(collection.blocked_non_integral_program_address_space);
  detail += ", unsupported_function_shape=";
  detail += std::to_string(collection.blocked_unsupported_function_shape);
  detail += ")";
  if (collection.first_oversized_switch_targets != 0 && collection.max_switch_targets_limit != 0) {
    detail += "; first_oversized_switch_targets=";
    detail += std::to_string(collection.first_oversized_switch_targets);
    detail += ">";
    detail += std::to_string(collection.max_switch_targets_limit);
  }
}

llvm::BasicBlock& select_anchor_block(llvm::BasicBlock& source_block,
                                      llvm::ArrayRef<llvm::BasicBlock*> unique_targets) {
  if (&source_block != &source_block.getParent()->getEntryBlock()) { return source_block; }

  for (llvm::BasicBlock* target : unique_targets) {
    if (target != nullptr && target != &source_block) { return *target; }
  }

  return source_block;
}

bool is_legal_anchor_block(llvm::BasicBlock& source_block, llvm::BasicBlock& anchor_block) {
  return &anchor_block != &source_block.getParent()->getEntryBlock() ||
         &source_block != &source_block.getParent()->getEntryBlock();
}

void append_unique_target(llvm::SmallVectorImpl<llvm::BasicBlock*>& targets,
                          llvm::BasicBlock* target) {
  if (target == nullptr) { return; }

  if (std::find(targets.begin(), targets.end(), target) == targets.end()) {
    targets.push_back(target);
  }
}

bool has_unsupported_function_shape(const llvm::Function& function, std::string& detail) {
  if (function.hasPersonalityFn()) {
    detail = "contains EH personality";
    return true;
  }

  for (const llvm::BasicBlock& block : function) {
    if (block.isEHPad()) {
      detail = "contains EH pad";
      return true;
    }

    const llvm::Instruction* terminator = block.getTerminator();
    if (terminator == nullptr) {
      detail = "contains unterminated block";
      return true;
    }

    if (llvm::isa<llvm::InvokeInst>(terminator) || llvm::isa<llvm::CallBrInst>(terminator) ||
        llvm::isa<llvm::IndirectBrInst>(terminator) ||
        llvm::isa<llvm::CatchSwitchInst>(terminator) ||
        llvm::isa<llvm::CatchReturnInst>(terminator) ||
        llvm::isa<llvm::CleanupReturnInst>(terminator) || llvm::isa<llvm::ResumeInst>(terminator)) {
      detail = "contains EH or indirect terminator";
      return true;
    }

    for (const llvm::Instruction& instruction : block) {
      const auto* call = llvm::dyn_cast<llvm::CallInst>(&instruction);
      if (call != nullptr && call->isMustTailCall()) {
        detail = "contains musttail call";
        return true;
      }
    }
  }

  return false;
}

std::uint64_t derive_site_seed(const llvm::Function& function,
                               const indirect_dispatch_options& options,
                               std::size_t site_index) {
  std::uint64_t seed = options.seed;
  seed = mix_seed(seed, stable_hash_string(function.getName(), 0x696469735f6631ULL));
  seed = mix_seed(seed, static_cast<std::uint64_t>(site_index + 1));
  return seed;
}

site_collection collect_sites(const llvm::Function& function,
                              const indirect_dispatch_options& options) {
  if (!options.enabled) { return make_empty_site_collection("indirect_dispatch disabled"); }

  if (function.isDeclaration()) { return make_empty_site_collection("declaration"); }

  if (options.max_sites_per_function == 0) {
    return make_empty_site_collection("max_sites_per_function is zero");
  }

  if (!options.target_flattened_headers && !options.target_vm_dispatchers) {
    return make_empty_site_collection("all indirect dispatch targets disabled");
  }

  const llvm::Module* module = function.getParent();
  if (module == nullptr) { return make_empty_site_collection("detached function"); }

  const llvm::DataLayout& data_layout = module->getDataLayout();
  const unsigned program_address_space = data_layout.getProgramAddressSpace();
  if (data_layout.isNonIntegralAddressSpace(program_address_space)) {
    site_collection collection = make_empty_site_collection("non-integral program address space");
    collection.max_switch_targets_limit = options.max_switch_targets;
    collection.blocked_non_integral_program_address_space = 1;
    append_selection_summary(collection.detail, collection);
    append_skip_summary(collection.detail, collection);
    return collection;
  }

  std::string unsupported_detail;
  if (has_unsupported_function_shape(function, unsupported_detail)) {
    site_collection collection = make_empty_site_collection(std::move(unsupported_detail));
    collection.max_switch_targets_limit = options.max_switch_targets;
    collection.blocked_unsupported_function_shape = 1;
    append_selection_summary(collection.detail, collection);
    append_skip_summary(collection.detail, collection);
    return collection;
  }

  llvm::SmallVector<dispatch_site, 8> sites;
  std::size_t next_site_index = 0;
  std::size_t selected_branch_sites = 0;
  std::size_t selected_switch_sites = 0;
  std::size_t skipped_max_switch_targets = 0;
  std::size_t first_oversized_switch_targets = 0;
  for (const llvm::BasicBlock& block : function) {
    if (sites.size() >= options.max_sites_per_function) { break; }

    const llvm::Instruction* terminator = block.getTerminator();
    if (terminator == nullptr) { continue; }

    if (options.target_flattened_headers) {
      const auto* branch = llvm::dyn_cast<llvm::BranchInst>(terminator);
      if (branch != nullptr && branch->isConditional()) {
        dispatch_site site;
        site.kind = dispatch_site_kind::branch;
        site.terminator = const_cast<llvm::Instruction*>(terminator);
        append_unique_target(site.unique_targets, branch->getSuccessor(0));
        append_unique_target(site.unique_targets, branch->getSuccessor(1));
        site.seed = derive_site_seed(function, options, next_site_index++);
        sites.push_back(std::move(site));
        ++selected_branch_sites;
        continue;
      }
    }

    if (!options.target_vm_dispatchers) { continue; }

    const auto* switch_inst = llvm::dyn_cast<llvm::SwitchInst>(terminator);
    if (switch_inst == nullptr || switch_inst->getNumCases() == 0) { continue; }

    if (switch_inst->getNumCases() + 1 > options.max_switch_targets) {
      ++skipped_max_switch_targets;
      if (first_oversized_switch_targets == 0) {
        first_oversized_switch_targets = switch_inst->getNumCases() + 1;
      }
      continue;
    }

    dispatch_site site;
    site.kind = dispatch_site_kind::switch_dispatch;
    site.terminator = const_cast<llvm::Instruction*>(terminator);
    site.default_target = const_cast<llvm::BasicBlock*>(switch_inst->getDefaultDest());
    append_unique_target(site.unique_targets, site.default_target);
    for (const auto& case_handle : switch_inst->cases()) {
      append_unique_target(site.unique_targets,
                           const_cast<llvm::BasicBlock*>(case_handle.getCaseSuccessor()));
    }
    site.seed = derive_site_seed(function, options, next_site_index++);
    sites.push_back(std::move(site));
    ++selected_switch_sites;
  }

  if (sites.empty()) {
    site_collection collection = make_empty_site_collection("no supported branch or switch sites");
    collection.max_switch_targets_limit = options.max_switch_targets;
    collection.selected_branch_sites = selected_branch_sites;
    collection.selected_switch_sites = selected_switch_sites;
    collection.skipped_max_switch_targets = skipped_max_switch_targets;
    collection.first_oversized_switch_targets = first_oversized_switch_targets;
    append_selection_summary(collection.detail, collection);
    append_skip_summary(collection.detail, collection);
    return collection;
  }

  const auto site_count = sites.size();
  site_collection collection{.sites = std::move(sites),
                             .detail = std::to_string(site_count) + " site(s) selected",
                             .selected_branch_sites = selected_branch_sites,
                             .selected_switch_sites = selected_switch_sites,
                             .skipped_max_switch_targets = skipped_max_switch_targets};
  collection.max_switch_targets_limit = options.max_switch_targets;
  collection.first_oversized_switch_targets = first_oversized_switch_targets;
  append_selection_summary(collection.detail, collection);
  append_skip_summary(collection.detail, collection);
  return collection;
}

site_masking materialize_site_tokens(llvm::Function& function,
                                     llvm::BasicBlock& anchor_block,
                                     llvm::ArrayRef<llvm::BasicBlock*> unique_targets,
                                     llvm::IRBuilder<llvm::NoFolder>& site_builder,
                                     const mba::builder_context& mba_context,
                                     std::uint64_t site_seed,
                                     std::size_t site_index) {
  const llvm::DataLayout& data_layout = function.getParent()->getDataLayout();
  const unsigned program_address_space = data_layout.getProgramAddressSpace();
  auto* int_type = llvm::cast<llvm::IntegerType>(
      data_layout.getIntPtrType(function.getContext(), program_address_space));

  const unsigned bit_width = int_type->getBitWidth();
  const unsigned rotate_amount =
      bit_width > 1
          ? 1U + static_cast<unsigned>(mix_seed(site_seed, 0x726f745f7331ULL) % (bit_width - 1U))
          : 0U;

  llvm::ConstantInt* key_constant =
      llvm::ConstantInt::get(int_type, mix_seed(site_seed, 0x6b65795f7331ULL));
  llvm::ConstantInt* bias_constant =
      llvm::ConstantInt::get(int_type, mix_seed(site_seed, 0x626961735f7331ULL));
  const bool use_affine_delta = mba_context.depth >= 2 && bit_width > 1;
  llvm::ConstantInt* affine_multiplier_constant = nullptr;
  llvm::ConstantInt* affine_bias_constant = nullptr;
  llvm::ConstantInt* affine_inverse_constant = nullptr;
  if (use_affine_delta) {
    const llvm::APInt affine_multiplier =
        support::make_odd_affine_multiplier(bit_width, mix_seed(site_seed, 0x616666696e652e6dULL));
    const llvm::APInt affine_bias =
        support::make_affine_bias(bit_width, mix_seed(site_seed, 0x616666696e652e62ULL));
    affine_multiplier_constant =
        llvm::cast<llvm::ConstantInt>(llvm::ConstantInt::get(int_type, affine_multiplier));
    affine_bias_constant =
        llvm::cast<llvm::ConstantInt>(llvm::ConstantInt::get(int_type, affine_bias));
    affine_inverse_constant = llvm::cast<llvm::ConstantInt>(
        llvm::ConstantInt::get(int_type, support::compute_mod_inverse_pow2(affine_multiplier)));
  }

  site_masking masking;
  masking.int_type = int_type;
  masking.pointer_type = llvm::BlockAddress::get(&function, &anchor_block)->getType();
  masking.key_constant = key_constant;
  masking.bias_constant = bias_constant;
  masking.affine_multiplier_constant = affine_multiplier_constant;
  masking.affine_bias_constant = affine_bias_constant;
  masking.affine_inverse_constant = affine_inverse_constant;
  masking.use_affine_delta = use_affine_delta;
  masking.rotate_amount = rotate_amount;

  llvm::Constant* anchor_address = llvm::BlockAddress::get(&function, &anchor_block);
  llvm::Constant* anchor_int = llvm::ConstantExpr::getPtrToInt(anchor_address, int_type);

  for (std::size_t target_index = 0; target_index < unique_targets.size(); ++target_index) {
    llvm::BasicBlock* target = unique_targets[target_index];
    llvm::Constant* target_address = llvm::BlockAddress::get(&function, target);
    llvm::Constant* target_int = llvm::ConstantExpr::getPtrToInt(target_address, int_type);
    llvm::Constant* delta = llvm::ConstantExpr::getSub(target_int, anchor_int);
    llvm::Value* encoded_delta = delta;
    if (use_affine_delta) {
      llvm::Value* scaled_delta = site_builder.CreateMul(
          delta,
          affine_multiplier_constant,
          support::scoped_ir_name(std::string("obf.idis.site") + std::to_string(site_index),
                                  "aff.mul" + std::to_string(target_index)));
      encoded_delta = site_builder.CreateAdd(
          scaled_delta,
          affine_bias_constant,
          support::scoped_ir_name(std::string("obf.idis.site") + std::to_string(site_index),
                                  "aff.enc" + std::to_string(target_index)));
    }

    llvm::Value* xored = site_builder.CreateXor(
        encoded_delta,
        key_constant,
        support::scoped_ir_name(std::string("obf.idis.site") + std::to_string(site_index),
                                "xor" + std::to_string(target_index)));
    llvm::Value* rotated = support::rotate_left_scalar(
        site_builder,
        xored,
        rotate_amount,
        support::scoped_ir_name(std::string("obf.idis.site") + std::to_string(site_index),
                                "rot" + std::to_string(target_index)));
    llvm::Value* encoded = site_builder.CreateAdd(
        rotated,
        bias_constant,
        support::scoped_ir_name(std::string("obf.idis.site") + std::to_string(site_index),
                                "tok" + std::to_string(target_index)));
    masking.encoded_tokens[target] = encoded;
  }

  return masking;
}

llvm::Value* decode_selected_token(llvm::IRBuilder<>& builder,
                                   llvm::Function& function,
                                   llvm::BasicBlock& anchor_block,
                                   llvm::Value* selected_token,
                                   const site_masking& masking,
                                   const mba::builder_context& mba_context,
                                   std::uint64_t salt_base) {
  llvm::Value* unbiased = mba::create_sub(builder,
                                          selected_token,
                                          masking.bias_constant,
                                          mba_context,
                                          salt_base ^ 0x11ULL,
                                          "obf.idis.unbias");
  llvm::Value* rotated =
      support::rotate_right_scalar(builder, unbiased, masking.rotate_amount, "obf.idis.rot");
  llvm::Value* delta = mba::create_xor(
      builder, rotated, masking.key_constant, mba_context, salt_base ^ 0x23ULL, "obf.idis.delta");
  if (masking.use_affine_delta) {
    llvm::Value* affine_sub = mba::create_sub(builder,
                                              delta,
                                              masking.affine_bias_constant,
                                              mba_context,
                                              salt_base ^ 0x2dULL,
                                              "obf.idis.affine.sub");
    delta = mba::create_mul(builder,
                            affine_sub,
                            masking.affine_inverse_constant,
                            mba_context,
                            salt_base ^ 0x2fULL,
                            "obf.idis.affine.dec");
  }
  llvm::Value* anchor = builder.CreatePtrToInt(
      llvm::BlockAddress::get(&function, &anchor_block), masking.int_type, "obf.idis.anchor");
  llvm::Value* dest_int =
      mba::create_add(builder, anchor, delta, mba_context, salt_base ^ 0x35ULL, "obf.idis.addr");
  return builder.CreateIntToPtr(dest_int, masking.pointer_type, "obf.idis.dest");
}

bool rewrite_branch_site(llvm::BranchInst& branch,
                         const mba::builder_context& mba_context,
                         std::uint64_t site_seed,
                         std::size_t site_index) {
  if (!branch.isConditional()) { return false; }

  llvm::BasicBlock& source_block = *branch.getParent();
  llvm::Function& function = *source_block.getParent();
  llvm::SmallVector<llvm::BasicBlock*, 2> unique_targets;
  append_unique_target(unique_targets, branch.getSuccessor(0));
  append_unique_target(unique_targets, branch.getSuccessor(1));
  llvm::BasicBlock& anchor_block = select_anchor_block(source_block, unique_targets);
  if (!is_legal_anchor_block(source_block, anchor_block)) { return false; }

  llvm::IRBuilder<llvm::NoFolder> materialize_builder(function.getContext(), llvm::NoFolder());
  materialize_builder.SetInsertPoint(&branch);
  const site_masking masking = materialize_site_tokens(function,
                                                       anchor_block,
                                                       unique_targets,
                                                       materialize_builder,
                                                       mba_context,
                                                       site_seed,
                                                       site_index);

  llvm::IRBuilder<> builder(function.getContext());
  builder.SetInsertPoint(&branch);

  llvm::Value* frozen_condition = builder.CreateFreeze(branch.getCondition(), "obf.idis.cond");
  llvm::Value* selected_token =
      builder.CreateSelect(frozen_condition,
                           masking.encoded_tokens.lookup(branch.getSuccessor(0)),
                           masking.encoded_tokens.lookup(branch.getSuccessor(1)),
                           "obf.idis.sel");
  llvm::Value* destination = decode_selected_token(
      builder, function, anchor_block, selected_token, masking, mba_context, site_seed);

  llvm::IndirectBrInst* indirect_branch =
      builder.CreateIndirectBr(destination, unique_targets.size());
  for (llvm::BasicBlock* target : unique_targets) { indirect_branch->addDestination(target); }

  branch.eraseFromParent();
  return true;
}

llvm::SmallVector<std::size_t, 8> seeded_case_order(std::size_t n, std::uint64_t site_seed) {
  llvm::SmallVector<std::size_t, 8> order;
  order.reserve(n);
  for (std::size_t i = 0; i < n; ++i) { order.push_back(i); }
  for (std::size_t i = n; i > 1; --i) {
    const std::uint64_t r =
        mix_seed(site_seed, 0x6f7264725f7331ULL ^ static_cast<std::uint64_t>(i));
    const std::size_t j = static_cast<std::size_t>(r % i);
    const std::size_t tmp = order[i - 1];
    order[i - 1] = order[j];
    order[j] = tmp;
  }
  return order;
}

llvm::Value* reduce_or_balanced(llvm::IRBuilder<>& builder,
                                llvm::ArrayRef<llvm::Value*> terms,
                                llvm::StringRef base) {
  llvm::SmallVector<llvm::Value*, 8> level(terms.begin(), terms.end());
  std::size_t round = 0;
  while (level.size() > 1) {
    llvm::SmallVector<llvm::Value*, 8> next;
    for (std::size_t i = 0; i + 1 < level.size(); i += 2) {
      next.push_back(
          builder.CreateOr(level[i],
                           level[i + 1],
                           base.str() + std::to_string(round) + "_" + std::to_string(i / 2)));
    }
    if (level.size() % 2 == 1) { next.push_back(level.back()); }
    level.assign(next.begin(), next.end());
    ++round;
  }
  return level.front();
}

bool rewrite_switch_site(llvm::SwitchInst& switch_inst,
                         const mba::builder_context& mba_context,
                         std::uint64_t site_seed,
                         std::size_t site_index) {
  llvm::BasicBlock& source_block = *switch_inst.getParent();
  llvm::Function& function = *source_block.getParent();

  llvm::SmallVector<llvm::BasicBlock*, 8> unique_targets;
  append_unique_target(unique_targets, switch_inst.getDefaultDest());
  for (const auto& case_handle : switch_inst.cases()) {
    append_unique_target(unique_targets, case_handle.getCaseSuccessor());
  }
  llvm::BasicBlock& anchor_block = select_anchor_block(source_block, unique_targets);
  if (!is_legal_anchor_block(source_block, anchor_block)) { return false; }

  llvm::IRBuilder<llvm::NoFolder> materialize_builder(function.getContext(), llvm::NoFolder());
  materialize_builder.SetInsertPoint(&switch_inst);
  const site_masking masking = materialize_site_tokens(function,
                                                       anchor_block,
                                                       unique_targets,
                                                       materialize_builder,
                                                       mba_context,
                                                       site_seed,
                                                       site_index);

  llvm::IRBuilder<> builder(function.getContext());
  builder.SetInsertPoint(&switch_inst);

  llvm::Value* frozen_state = builder.CreateFreeze(switch_inst.getCondition(), "obf.idis.state");
  llvm::Value* default_token = masking.encoded_tokens.lookup(switch_inst.getDefaultDest());

  struct case_entry {
    llvm::ConstantInt* value;
    llvm::BasicBlock* successor;
  };
  llvm::SmallVector<case_entry, 8> entries;
  for (const auto& case_handle : switch_inst.cases()) {
    entries.push_back({case_handle.getCaseValue(), case_handle.getCaseSuccessor()});
  }
  const llvm::SmallVector<std::size_t, 8> order = seeded_case_order(entries.size(), site_seed);

  llvm::ConstantInt* zero_token = llvm::ConstantInt::get(masking.int_type, 0);
  llvm::SmallVector<llvm::Value*, 8> candidates;
  llvm::SmallVector<llvm::Value*, 8> hits;
  for (std::size_t p = 0; p < order.size(); ++p) {
    const case_entry& e = entries[order[p]];
    llvm::Value* is_match =
        builder.CreateICmpEQ(frozen_state, e.value, "obf.idis.case" + std::to_string(p));
    llvm::Value* token = masking.encoded_tokens.lookup(e.successor);
    llvm::Value* cand =
        builder.CreateSelect(is_match, token, zero_token, "obf.idis.cand" + std::to_string(p));
    hits.push_back(is_match);
    candidates.push_back(cand);
  }
  llvm::Value* combined = reduce_or_balanced(builder, candidates, "obf.idis.acc");
  llvm::Value* any_match = reduce_or_balanced(builder, hits, "obf.idis.hit");
  llvm::Value* selected_token =
      builder.CreateSelect(any_match, combined, default_token, "obf.idis.sel");

  llvm::Value* destination = decode_selected_token(
      builder, function, anchor_block, selected_token, masking, mba_context, site_seed);

  llvm::IndirectBrInst* indirect_branch =
      builder.CreateIndirectBr(destination, unique_targets.size());
  for (llvm::BasicBlock* target : unique_targets) { indirect_branch->addDestination(target); }

  switch_inst.eraseFromParent();
  return true;
}

}  // namespace

indirect_dispatch_result analyze_indirect_dispatch(const llvm::Function& function,
                                                   const indirect_dispatch_options& options) {
  const site_collection collection = collect_sites(function, options);
  indirect_dispatch_result result;
  result.first_oversized_switch_targets = collection.first_oversized_switch_targets;
  result.max_switch_targets_limit = collection.max_switch_targets_limit;
  result.skipped_max_switch_targets = collection.skipped_max_switch_targets;
  result.blocked_non_integral_program_address_space =
      collection.blocked_non_integral_program_address_space;
  result.blocked_unsupported_function_shape = collection.blocked_unsupported_function_shape;
  result.detail = collection.detail;
  for (const dispatch_site& site : collection.sites) {
    ++result.site_count;
    if (site.kind == dispatch_site_kind::branch) {
      ++result.branch_site_count;
    } else {
      ++result.switch_site_count;
    }
  }
  if (result.site_count == 0 && result.detail.empty()) {
    result.detail = "no supported branch or switch sites";
  }
  return result;
}

indirect_dispatch_result run_indirect_dispatch(llvm::Function& function,
                                               const indirect_dispatch_options& options) {
  const site_collection collection = collect_sites(function, options);
  indirect_dispatch_result result;
  result.first_oversized_switch_targets = collection.first_oversized_switch_targets;
  result.max_switch_targets_limit = collection.max_switch_targets_limit;
  result.skipped_max_switch_targets = collection.skipped_max_switch_targets;
  result.blocked_non_integral_program_address_space =
      collection.blocked_non_integral_program_address_space;
  result.blocked_unsupported_function_shape = collection.blocked_unsupported_function_shape;
  if (collection.sites.empty()) {
    result.detail = collection.detail;
    return result;
  }

  auto mba_context = obf::support::make_mba_context(function,
                                                    "obf.idis",
                                                    options.seed,
                                                    {options.mba_depth,
                                                     options.mba_max_ir_instructions,
                                                     options.mba_enable_polynomial,
                                                     options.mba_enable_multiplication});

  for (std::size_t site_index = 0; site_index < collection.sites.size(); ++site_index) {
    const dispatch_site& site = collection.sites[site_index];
    bool rewritten = false;
    if (site.kind == dispatch_site_kind::branch) {
      rewritten = rewrite_branch_site(
          *llvm::cast<llvm::BranchInst>(site.terminator), mba_context, site.seed, site_index);
      if (rewritten) { ++result.branch_site_count; }
    } else {
      rewritten = rewrite_switch_site(
          *llvm::cast<llvm::SwitchInst>(site.terminator), mba_context, site.seed, site_index);
      if (rewritten) { ++result.switch_site_count; }
    }

    if (rewritten) { ++result.site_count; }
  }

  if (result.site_count == 0) {
    result.detail = collection.detail;
    return result;
  }

  result.detail = make_result_detail(result, "anchor-delta indirect dispatch");
  return result;
}

}  // namespace obf
