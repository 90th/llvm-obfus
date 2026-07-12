#include "obf/transforms/control_flattening.h"

#include "obf/support/affine_helpers.h"
#include "obf/support/decoy_trap.h"
#include "obf/support/flattening_metadata.h"
#include "obf/support/ir_name.h"
#include "obf/support/mba_config_builder.h"
#include "obf/support/stable_hash.h"
#include "obf/transforms/cfg_state_placeholders.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace obf {

namespace {

struct carried_value {
  llvm::Value* original = nullptr;
  llvm::PHINode* dispatcher_phi = nullptr;
};

struct transition_edge {
  llvm::BasicBlock* source = nullptr;
  llvm::BasicBlock* successor = nullptr;
  llvm::BasicBlock* block = nullptr;
  llvm::Value* next_state = nullptr;
};

// Pre-mutation snapshot of the SSA edges threaded across the dispatcher. It is
// captured before any use replacement so that dispatcher-PHI wiring always reads
// the ORIGINAL incoming value of each flattened PHI, never an operand mutated in
// place. Rewriting an original PHI operand and later reading it back is the
// ordering hazard this plan exists to remove.
struct flattening_ssa_plan {
  llvm::DenseMap<std::pair<llvm::PHINode*, llvm::BasicBlock*>, llvm::Value*> phi_incomings;

  void snapshot(llvm::ArrayRef<llvm::PHINode*> original_phis) {
    for (llvm::PHINode* phi : original_phis) {
      for (unsigned index = 0; index < phi->getNumIncomingValues(); ++index) {
        phi_incomings[{phi, phi->getIncomingBlock(index)}] = phi->getIncomingValue(index);
      }
    }
  }

  llvm::Value* incoming_value(llvm::PHINode* phi, llvm::BasicBlock* predecessor) const {
    const auto it = phi_incomings.find({phi, predecessor});
    assert(it != phi_incomings.end() &&
           "flattening SSA plan is missing an incoming value for a carried PHI edge");
    return it->second;
  }
};

enum class state_encoding_family : std::uint8_t { add_zero, sub_zero, xor_zero };

struct state_encoding_decision {
  state_encoding_family family;
  std::uint64_t salt_base;
};

state_encoding_decision choose_state_encoding_decision(std::uint64_t function_seed,
                                                       std::size_t site_ordinal) {
  const std::size_t family_index = ((function_seed % 3U) + (site_ordinal % 3U)) % 3U;
  state_encoding_family family = state_encoding_family::add_zero;
  switch (family_index) {
    case 0:
      family = state_encoding_family::add_zero;
      break;
    case 1:
      family = state_encoding_family::sub_zero;
      break;
    case 2:
      family = state_encoding_family::xor_zero;
      break;
  }

  return {
      .family = family,
      .salt_base = mix_seed(
          function_seed, (static_cast<std::uint64_t>(site_ordinal) + 1U) * 0x9e3779b97f4a7c15ULL),
  };
}

struct decoy_state {
  std::uint32_t id = 0;
  llvm::BasicBlock* entry = nullptr;
};

struct dispatch_case {
  std::uint32_t state_id = 0;
  llvm::BasicBlock* target = nullptr;
};

struct dispatch_tree_state {
  std::size_t next_ordinal = 0;
};

enum class dispatch_equality_family : std::uint8_t { xor_mask, affine };
enum class dispatch_order_family : std::uint8_t { sign_mask, subtract_borrow };

struct dispatch_node_decision {
  dispatch_equality_family equality_family;
  dispatch_order_family order_family;
  std::uint64_t salt_base;
};

struct dispatch_tree_context {
  llvm::Function& function;
  llvm::Value* state_value = nullptr;
  llvm::BasicBlock* default_target = nullptr;
  const mba::builder_context& mba_context;
  dispatch_tree_state& tree_state;
};

std::mt19937 build_state_rng(const llvm::Function& function,
                             const control_flattening_options& options) {
  const std::uint64_t seed_base = options.seed == 0 ? 0x6d2534f1f6c7a29bULL : options.seed;
  const std::uint64_t mixed_seed = mix_seed(seed_base, stable_hash_string(function.getName()));
  std::seed_seq seed_words{static_cast<std::uint32_t>(mixed_seed),
                           static_cast<std::uint32_t>(mixed_seed >> 32),
                           static_cast<std::uint32_t>(function.arg_size()),
                           static_cast<std::uint32_t>(function.size())};
  return std::mt19937(seed_words);
}

std::uint32_t generate_sparse_state_id(std::mt19937& rng, llvm::DenseSet<std::uint32_t>& used_ids) {
  while (true) {
    std::uint32_t candidate = rng();
    candidate |= 0x01010101U;
    if (candidate == 0 || !used_ids.insert(candidate).second) { continue; }

    return candidate;
  }
}

std::size_t choose_decoy_count(std::size_t block_count, const control_flattening_options& options) {
  if (options.max_decoy_states == 0 || block_count == 0) { return 0; }

  return std::min<std::size_t>(options.max_decoy_states, std::max<std::size_t>(1, block_count / 2));
}

bool instruction_escapes_block(const llvm::Instruction& instruction) {
  for (const llvm::User* user : instruction.users()) {
    const auto* user_instruction = llvm::dyn_cast<llvm::Instruction>(user);
    if (user_instruction == nullptr) { return true; }

    if (user_instruction->getParent() == instruction.getParent()) {
      if (llvm::isa<llvm::PHINode>(user_instruction)) { return true; }

      continue;
    }

    // Original PHIs are carried explicitly. Re-carrying values that only feed
    // PHIs in another block creates redundant dispatcher PHI chains and can
    // corrupt the threaded value after flattening.
    if (llvm::isa<llvm::PHINode>(user_instruction)) { continue; }

    if (user_instruction->getParent() != instruction.getParent()) { return true; }
  }

  return false;
}

bool has_supported_terminators_only(const llvm::Function& function,
                                    std::size_t& conditional_branches) {
  conditional_branches = 0;

  for (const llvm::BasicBlock& block : function) {
    const llvm::Instruction* terminator = block.getTerminator();
    if (terminator == nullptr) { return false; }

    if (llvm::isa<llvm::ReturnInst>(terminator) || llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    if (const auto* branch = llvm::dyn_cast<llvm::BranchInst>(terminator)) {
      if (branch->isConditional()) { ++conditional_branches; }
      continue;
    }

    return false;
  }

  return true;
}

void hoist_entry_allocas_to_setup(llvm::BasicBlock& entry, llvm::BasicBlock& setup) {
  llvm::Instruction* insert_before = setup.getTerminator();
  llvm::SmallVector<llvm::AllocaInst*, 8> allocas;

  for (llvm::Instruction& instruction : entry) {
    auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (alloca == nullptr) { break; }

    allocas.push_back(alloca);
  }

  for (llvm::AllocaInst* alloca : allocas) { alloca->moveBefore(insert_before->getIterator()); }
}

llvm::Value* encode_state_id(llvm::IRBuilder<>& builder,
                             const mba::builder_context& base_context,
                             const state_encoding_decision& decision,
                             std::uint32_t state_id) {
  mba::builder_context context = base_context;
  context.depth = std::max<std::uint32_t>(context.depth, 2);
  llvm::Value* encoded_state =
      mba::create_opaque_integer(builder,
                                 builder.getInt32Ty(),
                                 context,
                                 llvm::APInt(32, static_cast<std::uint64_t>(state_id)),
                                 decision.salt_base,
                                 "obf.flat.state.opaque");
  llvm::Value* encoded_zero = mba::create_opaque_integer(builder,
                                                         builder.getInt32Ty(),
                                                         context,
                                                         llvm::APInt(32, 0),
                                                         decision.salt_base ^ 0x9e3779b9ULL,
                                                         "obf.flat.state.zero");
  const std::uint64_t operation_salt = decision.salt_base ^ 0xa55aa55aULL;
  switch (decision.family) {
    case state_encoding_family::add_zero:
      return mba::create_add(
          builder, encoded_state, encoded_zero, context, operation_salt, "obf.flat.state.next.add");
    case state_encoding_family::sub_zero:
      return mba::create_sub(
          builder, encoded_state, encoded_zero, context, operation_salt, "obf.flat.state.next.sub");
    case state_encoding_family::xor_zero:
      return mba::create_xor(
          builder, encoded_state, encoded_zero, context, operation_salt, "obf.flat.state.next.xor");
  }

  llvm_unreachable("unknown state encoding family");
}

llvm::Value* build_true_opaque_predicate(llvm::IRBuilder<>& builder,
                                         llvm::Function& function,
                                         std::uint32_t mba_depth,
                                         std::uint64_t salt_base,
                                         std::optional<std::uint32_t> max_ir,
                                         std::optional<bool> poly,
                                         std::optional<bool> mul) {
  return mba::build_entropy_true_predicate(builder,
                                           function,
                                           mba_depth,
                                           salt_base,
                                           0x31415926ULL,
                                           0x27182818ULL,
                                           "obf.flat.decoy.a",
                                           "obf.flat.decoy.b",
                                           "obf.flat.decoy.true",
                                           max_ir,
                                           poly,
                                           mul);
}

llvm::BasicBlock* create_decoy_trap(llvm::Function& function,
                                    std::uint32_t mba_depth,
                                    std::uint64_t salt_base,
                                    std::optional<std::uint32_t> max_ir,
                                    std::optional<bool> poly,
                                    std::optional<bool> mul) {
  llvm::Module* module = function.getParent();
  if (module == nullptr) { return nullptr; }

  llvm::LLVMContext& context = function.getContext();
  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "obf.flat.decoy", &function);
  llvm::BasicBlock* loop = llvm::BasicBlock::Create(context, "obf.flat.decoy.loop", &function);
  llvm::BasicBlock* trap = llvm::BasicBlock::Create(context, "obf.flat.decoy.trap", &function);

  llvm::IRBuilder<> entry_builder(entry);
  llvm::Value* entropy = entry_builder.CreateLoad(entry_builder.getInt64Ty(),
                                                  mba::get_or_create_entropy_anchor(*module),
                                                  "obf.flat.decoy.entropy");
  llvm::Value* initial_state =
      entry_builder.CreateXor(entropy,
                              llvm::ConstantInt::get(entry_builder.getInt64Ty(),
                                                     mix_seed(salt_base, 0xd6e8feb86659fd93ULL)),
                              "obf.flat.decoy.state.init");
  entry_builder.CreateBr(loop);
  flattening::tag_block(*entry, flattening::block_role::decoy);

  llvm::IRBuilder<> loop_builder(loop);
  llvm::PHINode* iteration =
      loop_builder.CreatePHI(loop_builder.getInt32Ty(), 2, "obf.flat.decoy.iter");
  llvm::PHINode* state =
      loop_builder.CreatePHI(loop_builder.getInt64Ty(), 2, "obf.flat.decoy.state");
  auto loop_state =
      support::build_decoy_loop_core(loop_builder, state, iteration, "obf.flat.decoy");
  llvm::Value* predicate = build_true_opaque_predicate(
      loop_builder, function, mba_depth, salt_base + 0x71ULL, max_ir, poly, mul);
  const std::uint32_t decoy_iteration_limit =
      256U +
      static_cast<std::uint32_t>(
          mix_seed(salt_base, stable_hash_string(function.getName()) ^ function.size()) % 1024ULL);
  llvm::Value* below_limit = loop_builder.CreateICmpULT(
      iteration,
      llvm::ConstantInt::get(loop_builder.getInt32Ty(), decoy_iteration_limit),
      "obf.flat.decoy.below_limit");
  llvm::Value* continue_loop =
      loop_builder.CreateAnd(predicate, below_limit, "obf.flat.decoy.cont");
  loop_builder.CreateCondBr(continue_loop, loop, trap);
  flattening::tag_block(*loop, flattening::block_role::decoy);

  iteration->addIncoming(llvm::ConstantInt::get(loop_builder.getInt32Ty(), 0), entry);
  iteration->addIncoming(loop_state.next_iteration, loop);
  state->addIncoming(initial_state, entry);
  state->addIncoming(loop_state.next_state, loop);

  llvm::IRBuilder<> trap_builder(trap);
  trap_builder.CreateCall(llvm::Intrinsic::getOrInsertDeclaration(module, llvm::Intrinsic::trap));
  trap_builder.CreateUnreachable();
  flattening::tag_block(*trap, flattening::block_role::decoy);
  return entry;
}

// Map a concrete SSA value that is live on the `source`->`successor` edge to the
// value the dispatcher PHI must carry. Original PHIs are erased by flattening, so
// any PHI is routed through its dispatcher PHI. A non-PHI instruction defined in
// `source` still dominates the edge block, so its fresh, current value is used
// directly; any other carried value is routed through its dispatcher PHI.
llvm::Value*
map_flattened_edge_value(llvm::Value* value,
                         llvm::BasicBlock* source,
                         const llvm::DenseMap<llvm::Value*, llvm::PHINode*>& dispatcher_phis) {
  if (llvm::isa<llvm::PHINode>(value)) {
    if (const auto it = dispatcher_phis.find(value); it != dispatcher_phis.end()) {
      return it->second;
    }

    return value;
  }

  auto* instruction = llvm::dyn_cast<llvm::Instruction>(value);
  if (instruction == nullptr) { return value; }

  if (instruction->getParent() == source) { return instruction; }

  if (const auto it = dispatcher_phis.find(instruction); it != dispatcher_phis.end()) {
    return it->second;
  }

  return instruction;
}

llvm::Value*
translate_value_for_edge(llvm::Value* value,
                         llvm::BasicBlock* source,
                         llvm::BasicBlock* successor,
                         const llvm::DenseMap<llvm::Value*, llvm::PHINode*>& dispatcher_phis,
                         const flattening_ssa_plan& plan) {
  // A carried PHI in the successor selects, on this edge, its incoming value for
  // `source`. Resolve that ORIGINAL incoming from the pre-mutation snapshot (never
  // from the live operand, which the use-replacement pass must leave untouched),
  // then map it to the value the dispatcher PHI should carry.
  if (auto* phi = llvm::dyn_cast<llvm::PHINode>(value);
      phi != nullptr && phi->getParent() == successor) {
    return map_flattened_edge_value(plan.incoming_value(phi, source), source, dispatcher_phis);
  }

  return map_flattened_edge_value(value, source, dispatcher_phis);
}

bool is_cfg_state_placeholder_call(const llvm::Instruction& instruction,
                                   llvm::StringRef expected_name) {
  const auto* call = llvm::dyn_cast<llvm::CallInst>(&instruction);
  if (call == nullptr) { return false; }

  const llvm::Function* callee = call->getCalledFunction();
  return callee != nullptr && callee->getName() == expected_name;
}

void bind_cfg_state_placeholders(llvm::ArrayRef<llvm::BasicBlock*> blocks,
                                 const llvm::DenseMap<llvm::BasicBlock*, std::uint32_t>& state_ids,
                                 llvm::PHINode* state_phi) {
  if (state_phi == nullptr) { return; }

  llvm::Type* state_type = state_phi->getType();
  for (llvm::BasicBlock* block : blocks) {
    if (block == nullptr) { continue; }

    llvm::SmallVector<llvm::Instruction*, 4> erase_list;
    for (llvm::Instruction& instruction : *block) {
      if (is_cfg_state_placeholder_call(instruction, kCfgStatePlaceholderName)) {
        instruction.replaceAllUsesWith(state_phi);
        erase_list.push_back(&instruction);
        continue;
      }

      if (is_cfg_state_placeholder_call(instruction, kExpectedCfgStatePlaceholderName)) {
        instruction.replaceAllUsesWith(llvm::ConstantInt::get(
            state_type, static_cast<std::uint64_t>(state_ids.lookup(block))));
        erase_list.push_back(&instruction);
      }
    }

    for (llvm::Instruction* instruction : erase_list) { instruction->eraseFromParent(); }
  }
}

std::vector<dispatch_case>
build_dispatch_cases(llvm::ArrayRef<llvm::BasicBlock*> blocks,
                     const llvm::DenseMap<llvm::BasicBlock*, std::uint32_t>& state_ids,
                     llvm::ArrayRef<decoy_state> decoy_states) {
  std::vector<dispatch_case> cases;
  cases.reserve(blocks.size() + decoy_states.size());
  for (llvm::BasicBlock* block : blocks) {
    if (block == nullptr) { continue; }

    cases.push_back({.state_id = state_ids.lookup(block), .target = block});
  }

  for (const decoy_state& decoy : decoy_states) {
    if (decoy.entry == nullptr) { continue; }

    cases.push_back({.state_id = decoy.id, .target = decoy.entry});
  }

  return cases;
}

void shuffle_dispatch_cases(std::vector<dispatch_case>& cases, std::mt19937& rng) {
  std::shuffle(cases.begin(), cases.end(), rng);
}

std::uint64_t build_dispatch_tree_salt(const mba::builder_context& mba_context,
                                       std::size_t depth,
                                       std::size_t ordinal,
                                       std::uint64_t family_salt) {
  std::uint64_t salt = mix_seed(mba_context.seed_base, family_salt);
  salt = mix_seed(salt, static_cast<std::uint64_t>(depth + 1));
  salt = mix_seed(salt, static_cast<std::uint64_t>(ordinal + 1) * 0x9e3779b97f4a7c15ULL);
  return salt;
}

dispatch_node_decision choose_dispatch_node_decision(const mba::builder_context& mba_context,
                                                     std::size_t depth,
                                                     std::size_t ordinal) {
  const bool odd_node = (ordinal & 1U) != 0;
  const bool affine = ((mba_context.seed_base & 1U) != 0) ^ odd_node;
  const bool subtract_borrow = (((mba_context.seed_base >> 1U) & 1U) != 0) ^ odd_node;
  return {
      .equality_family =
          affine ? dispatch_equality_family::affine : dispatch_equality_family::xor_mask,
      .order_family = subtract_borrow ? dispatch_order_family::subtract_borrow
                                      : dispatch_order_family::sign_mask,
      .salt_base = build_dispatch_tree_salt(mba_context, depth, ordinal, 0x1f4a7401ULL),
  };
}

llvm::Value* build_dispatch_equality(llvm::IRBuilder<>& builder,
                                     const dispatch_tree_context& context,
                                     std::uint32_t state_id,
                                     const dispatch_node_decision& decision) {
  llvm::Value* pivot =
      mba::create_opaque_integer(builder,
                                 builder.getInt32Ty(),
                                 context.mba_context,
                                 llvm::APInt(32, static_cast<std::uint64_t>(state_id)),
                                 decision.salt_base ^ 0x65717069766f74ULL,
                                 "obf.flat.dispatch.eq.pivot");

  switch (decision.equality_family) {
    case dispatch_equality_family::xor_mask: {
      const std::uint32_t mask =
          static_cast<std::uint32_t>(mix_seed(decision.salt_base, 0x65716d61736b76ULL)) | 1U;
      llvm::Value* opaque_mask =
          mba::create_opaque_integer(builder,
                                     builder.getInt32Ty(),
                                     context.mba_context,
                                     llvm::APInt(32, mask),
                                     decision.salt_base ^ 0x65716d61736b73ULL,
                                     "obf.flat.dispatch.eq.mask");
      llvm::Value* encoded_state =
          builder.CreateXor(context.state_value, opaque_mask, "obf.flat.dispatch.eq.state.xor");
      llvm::Value* encoded_pivot =
          builder.CreateXor(pivot, opaque_mask, "obf.flat.dispatch.eq.pivot.xor");
      return builder.CreateICmpEQ(encoded_state, encoded_pivot, "obf.flat.dispatch.eq.xor");
    }
    case dispatch_equality_family::affine: {
      const llvm::APInt multiplier =
          support::make_odd_affine_multiplier(32, mix_seed(decision.salt_base, 0x65716d756cULL));
      const llvm::APInt bias =
          support::make_affine_bias(32, mix_seed(decision.salt_base, 0x657162696173ULL));
      llvm::Value* encoded_state = support::build_affine_encode(
          builder, context.state_value, multiplier, bias, "obf.flat.dispatch.eq.state.affine");
      llvm::Value* encoded_pivot = support::build_affine_encode(
          builder, pivot, multiplier, bias, "obf.flat.dispatch.eq.pivot.affine");
      return builder.CreateICmpEQ(encoded_state, encoded_pivot, "obf.flat.dispatch.eq.affine");
    }
  }

  llvm_unreachable("unknown dispatch equality family");
}

llvm::Value* build_dispatch_order(llvm::IRBuilder<>& builder,
                                  const dispatch_tree_context& context,
                                  std::uint32_t state_id,
                                  const dispatch_node_decision& decision) {
  llvm::Value* pivot =
      mba::create_opaque_integer(builder,
                                 builder.getInt32Ty(),
                                 context.mba_context,
                                 llvm::APInt(32, static_cast<std::uint64_t>(state_id)),
                                 decision.salt_base ^ 0x6f72647069766f74ULL,
                                 "obf.flat.dispatch.order.pivot");

  switch (decision.order_family) {
    case dispatch_order_family::sign_mask: {
      llvm::Value* sign_mask = mba::create_opaque_integer(builder,
                                                          builder.getInt32Ty(),
                                                          context.mba_context,
                                                          llvm::APInt(32, 0x80000000U),
                                                          decision.salt_base ^ 0x6f72647369676eULL,
                                                          "obf.flat.dispatch.order.sign.mask");
      llvm::Value* signed_state =
          builder.CreateXor(context.state_value, sign_mask, "obf.flat.dispatch.order.state.sign");
      llvm::Value* signed_pivot =
          builder.CreateXor(pivot, sign_mask, "obf.flat.dispatch.order.pivot.sign");
      return builder.CreateICmpSLT(signed_state, signed_pivot, "obf.flat.dispatch.order.sign");
    }
    case dispatch_order_family::subtract_borrow: {
      llvm::Value* delta =
          builder.CreateSub(context.state_value, pivot, "obf.flat.dispatch.order.delta");
      return builder.CreateICmpUGT(delta, context.state_value, "obf.flat.dispatch.order.borrow");
    }
  }

  llvm_unreachable("unknown dispatch order family");
}

void emit_dispatch_subtree(llvm::BasicBlock& block,
                           const dispatch_tree_context& context,
                           std::vector<dispatch_case> cases,
                           std::size_t depth,
                           flattening::block_role role);

void emit_dispatch_leaf(llvm::BasicBlock& block,
                        const dispatch_tree_context& context,
                        const dispatch_case& single_case,
                        std::size_t depth,
                        std::size_t ordinal,
                        flattening::block_role role) {
  llvm::IRBuilder<> builder(&block);
  const dispatch_node_decision decision =
      choose_dispatch_node_decision(context.mba_context, depth, ordinal);
  llvm::Value* is_match = build_dispatch_equality(builder, context, single_case.state_id, decision);
  builder.CreateCondBr(is_match, single_case.target, context.default_target);
  flattening::tag_block(block, role);
}

void emit_dispatch_subtree(llvm::BasicBlock& block,
                           const dispatch_tree_context& context,
                           std::vector<dispatch_case> cases,
                           std::size_t depth,
                           flattening::block_role role) {
  if (cases.empty()) {
    llvm::IRBuilder<> builder(&block);
    builder.CreateBr(context.default_target);
    flattening::tag_block(block, role);
    return;
  }

  const std::size_t ordinal = context.tree_state.next_ordinal++;
  if (cases.size() == 1) {
    emit_dispatch_leaf(block, context, cases.front(), depth, ordinal, role);
    return;
  }

  std::vector<dispatch_case> ordered_cases = cases;
  std::sort(ordered_cases.begin(),
            ordered_cases.end(),
            [](const dispatch_case& lhs, const dispatch_case& rhs) {
              if (lhs.state_id != rhs.state_id) { return lhs.state_id < rhs.state_id; }
              return lhs.target < rhs.target;
            });
  const dispatch_case pivot = ordered_cases[ordered_cases.size() / 2];

  std::vector<dispatch_case> left_cases;
  std::vector<dispatch_case> right_cases;
  left_cases.reserve(cases.size() / 2);
  right_cases.reserve(cases.size() / 2);
  for (const dispatch_case& entry : cases) {
    if (entry.state_id < pivot.state_id) {
      left_cases.push_back(entry);
    } else if (entry.state_id > pivot.state_id) {
      right_cases.push_back(entry);
    }
  }

  llvm::BasicBlock* split_block =
      llvm::BasicBlock::Create(context.function.getContext(),
                               obf::support::scoped_ir_name("obf.flat.dispatch", "split", ordinal),
                               &context.function);
  llvm::BasicBlock* left_entry =
      left_cases.empty() ? nullptr
                         : llvm::BasicBlock::Create(
                               context.function.getContext(),
                               obf::support::scoped_ir_name("obf.flat.dispatch", "left", ordinal),
                               &context.function);
  llvm::BasicBlock* right_entry =
      right_cases.empty() ? nullptr
                          : llvm::BasicBlock::Create(
                                context.function.getContext(),
                                obf::support::scoped_ir_name("obf.flat.dispatch", "right", ordinal),
                                &context.function);

  const dispatch_node_decision decision =
      choose_dispatch_node_decision(context.mba_context, depth, ordinal);
  llvm::IRBuilder<> equality_builder(&block);
  llvm::Value* is_equal =
      build_dispatch_equality(equality_builder, context, pivot.state_id, decision);
  equality_builder.CreateCondBr(is_equal, pivot.target, split_block);

  llvm::IRBuilder<> split_builder(split_block);
  llvm::Value* is_less = build_dispatch_order(split_builder, context, pivot.state_id, decision);
  split_builder.CreateCondBr(is_less,
                             left_entry != nullptr ? left_entry : context.default_target,
                             right_entry != nullptr ? right_entry : context.default_target);
  flattening::tag_block(*split_block, flattening::block_role::dispatch_split);

  if (left_entry != nullptr) {
    emit_dispatch_subtree(
        *left_entry, context, left_cases, depth + 1, flattening::block_role::dispatch_left);
  }
  if (right_entry != nullptr) {
    emit_dispatch_subtree(
        *right_entry, context, right_cases, depth + 1, flattening::block_role::dispatch_right);
  }
  flattening::tag_block(block, role);
}

}  // namespace

control_flattening_result analyze_control_flattening(const llvm::Function& function,
                                                     const control_flattening_options& options) {
  if (function.isDeclaration()) { return {.flattened = false, .detail = "declaration"}; }

  if (function.size() < options.min_blocks) {
    return {.flattened = false, .detail = "too few basic blocks"};
  }

  if (function.size() > options.max_blocks) {
    return {.flattened = false, .detail = "too many basic blocks"};
  }

  std::size_t instruction_count = 0;
  for (const llvm::BasicBlock& block : function) {
    if (block.isEHPad()) { return {.flattened = false, .detail = "contains EH pad"}; }

    instruction_count += block.size();
  }

  if (instruction_count > options.max_instructions) {
    return {.flattened = false, .detail = "too many instructions"};
  }

  std::size_t conditional_branches = 0;
  if (!has_supported_terminators_only(function, conditional_branches)) {
    return {.flattened = false, .detail = "unsupported terminator kind"};
  }

  if (conditional_branches == 0) {
    return {.flattened = false, .detail = "no conditional branches"};
  }

  return {.flattened = true,
          .state_count = function.size(),
          .conditional_branches = conditional_branches,
          .detail = std::to_string(function.size()) + " state blocks"};
}

control_flattening_result run_control_flattening(llvm::Function& function,
                                                 const control_flattening_options& options) {
  const control_flattening_result analysis = analyze_control_flattening(function, options);
  if (!analysis.flattened) { return analysis; }

  llvm::BasicBlock* original_entry = &function.getEntryBlock();
  llvm::LLVMContext& context = function.getContext();
  llvm::BasicBlock* setup =
      llvm::BasicBlock::Create(context, "obf.flat.setup", &function, original_entry);
  llvm::BasicBlock* dispatch =
      llvm::BasicBlock::Create(context, "obf.flat.dispatch", &function, original_entry);
  llvm::IRBuilder<> setup_builder(setup);
  setup_builder.CreateBr(dispatch);
  flattening::tag_block(*setup, flattening::block_role::setup);
  hoist_entry_allocas_to_setup(*original_entry, *setup);

  std::vector<llvm::BasicBlock*> blocks;
  blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) {
    if (&block != setup && &block != dispatch) { blocks.push_back(&block); }
  }

  std::mt19937 state_rng = build_state_rng(function, options);
  llvm::DenseSet<std::uint32_t> used_state_ids;
  llvm::DenseMap<llvm::BasicBlock*, std::uint32_t> state_ids;
  for (llvm::BasicBlock* block : blocks) {
    state_ids[block] = generate_sparse_state_id(state_rng, used_state_ids);
  }

  const std::size_t decoy_count = choose_decoy_count(blocks.size(), options);
  std::vector<decoy_state> decoy_states;
  decoy_states.reserve(decoy_count);

  std::vector<carried_value> carried_values;
  carried_values.reserve(blocks.size());
  std::vector<llvm::PHINode*> original_phis;
  for (llvm::BasicBlock* block : blocks) {
    for (llvm::Instruction& instruction : *block) {
      if (auto* phi = llvm::dyn_cast<llvm::PHINode>(&instruction)) {
        original_phis.push_back(phi);
        carried_values.push_back({.original = phi});
        continue;
      }

      if (instruction.isTerminator() || instruction.getType()->isVoidTy() ||
          llvm::isa<llvm::AllocaInst>(instruction)) {
        continue;
      }

      if (instruction_escapes_block(instruction)) {
        carried_values.push_back({.original = &instruction});
      }
    }
  }

  // Snapshot every (original PHI, predecessor) -> incoming value BEFORE any use
  // replacement mutates operands. Dispatcher wiring reads exclusively from here.
  flattening_ssa_plan ssa_plan;
  ssa_plan.snapshot(original_phis);
  llvm::DenseSet<const llvm::PHINode*> original_phi_set;
  for (llvm::PHINode* phi : original_phis) { original_phi_set.insert(phi); }

  llvm::PHINode* state_phi =
      llvm::PHINode::Create(llvm::Type::getInt32Ty(context), 1, "obf.state", dispatch);
  llvm::DenseMap<llvm::Value*, llvm::PHINode*> dispatcher_phis;
  for (carried_value& carried : carried_values) {
    auto* phi = llvm::PHINode::Create(carried.original->getType(), 1, "obf.flat.val", dispatch);
    carried.dispatcher_phi = phi;
    dispatcher_phis[carried.original] = phi;
  }

  bind_cfg_state_placeholders(blocks, state_ids, state_phi);

  for (const carried_value& carried : carried_values) {
    auto* instruction = llvm::cast<llvm::Instruction>(carried.original);
    const bool carried_is_phi = llvm::isa<llvm::PHINode>(instruction);

    llvm::SmallVector<llvm::Use*, 8> uses;
    for (llvm::Use& use : carried.original->uses()) { uses.push_back(&use); }

    for (llvm::Use* use : uses) {
      auto* user_instruction = llvm::dyn_cast<llvm::Instruction>(use->getUser());
      if (user_instruction == nullptr) {
        use->set(carried.dispatcher_phi);
        continue;
      }

      // Never rewrite an operand inside an original PHI: it is a CFG-edge value
      // threaded by the SSA plan, and the PHI itself is erased afterwards.
      // Mutating it here is the ordering hazard that corrupted the threaded value.
      if (auto* user_phi = llvm::dyn_cast<llvm::PHINode>(user_instruction);
          user_phi != nullptr && original_phi_set.contains(user_phi)) {
        continue;
      }

      // A carried PHI is erased, so every surviving use must read its dispatcher
      // PHI. A carried non-PHI instruction survives; only its cross-block uses
      // need the dispatcher PHI, because its definition no longer dominates them.
      const bool replace_use =
          carried_is_phi || user_instruction->getParent() != instruction->getParent();
      if (replace_use) { use->set(carried.dispatcher_phi); }
    }
  }

  auto mba_context = obf::support::make_mba_context(function,
                                                    "obf.flat",
                                                    0x2f4d8f13ULL,
                                                    {options.mba_depth,
                                                     options.mba_max_ir_instructions,
                                                     options.mba_enable_polynomial,
                                                     options.mba_enable_multiplication});
  mba_context.seed_base = mix_seed(mba_context.seed_base, options.seed);

  for (std::size_t decoy_index = 0; decoy_index < decoy_count; ++decoy_index) {
    llvm::BasicBlock* decoy_entry =
        create_decoy_trap(function,
                          options.mba_depth,
                          mix_seed(options.seed, static_cast<std::uint64_t>(decoy_index + 1)),
                          options.mba_max_ir_instructions,
                          options.mba_enable_polynomial,
                          options.mba_enable_multiplication);
    if (decoy_entry == nullptr) { continue; }

    decoy_states.push_back(
        {.id = generate_sparse_state_id(state_rng, used_state_ids), .entry = decoy_entry});
  }

  std::vector<transition_edge> transition_edges;
  transition_edges.reserve(blocks.size() * 2);
  std::size_t state_encoding_ordinal = 0;
  for (llvm::BasicBlock* block : blocks) {
    llvm::Instruction* terminator = block->getTerminator();
    if (llvm::isa<llvm::ReturnInst>(terminator) || llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    auto* branch = llvm::cast<llvm::BranchInst>(terminator);
    llvm::SmallVector<transition_edge, 2> block_edges;
    for (unsigned successor_index = 0; successor_index < branch->getNumSuccessors();
         ++successor_index) {
      llvm::BasicBlock* successor = branch->getSuccessor(successor_index);
      llvm::BasicBlock* edge_block =
          llvm::BasicBlock::Create(context, "obf.flat.edge", &function, dispatch);
      llvm::IRBuilder<> edge_builder(edge_block);
      const state_encoding_decision encoding_decision =
          choose_state_encoding_decision(mba_context.seed_base, state_encoding_ordinal++);
      llvm::Value* next_state =
          encode_state_id(edge_builder, mba_context, encoding_decision, state_ids[successor]);
      edge_builder.CreateBr(dispatch);
      flattening::tag_block(*edge_block, flattening::block_role::edge);
      block_edges.push_back(
          {.source = block, .successor = successor, .block = edge_block, .next_state = next_state});
    }

    llvm::IRBuilder<> builder(branch);
    if (branch->isConditional()) {
      builder.CreateCondBr(branch->getCondition(), block_edges[0].block, block_edges[1].block);
    } else {
      builder.CreateBr(block_edges[0].block);
    }
    branch->eraseFromParent();

    transition_edges.insert(transition_edges.end(), block_edges.begin(), block_edges.end());
  }

  setup_builder.SetInsertPoint(setup->getTerminator());
  const state_encoding_decision setup_encoding_decision =
      choose_state_encoding_decision(mba_context.seed_base, state_encoding_ordinal++);
  state_phi->addIncoming(
      encode_state_id(
          setup_builder, mba_context, setup_encoding_decision, state_ids[original_entry]),
      setup);
  for (const carried_value& carried : carried_values) {
    carried.dispatcher_phi->addIncoming(llvm::PoisonValue::get(carried.original->getType()), setup);
  }

  for (const transition_edge& edge : transition_edges) {
    state_phi->addIncoming(edge.next_state, edge.block);
    for (const carried_value& carried : carried_values) {
      carried.dispatcher_phi->addIncoming(
          translate_value_for_edge(
              carried.original, edge.source, edge.successor, dispatcher_phis, ssa_plan),
          edge.block);
    }
  }

  // Invariants (debug/CI): the dispatcher has exactly one predecessor per original
  // transition edge plus the setup edge, and every dispatcher PHI (and the state
  // PHI) has exactly one incoming per dispatcher predecessor.
#ifndef NDEBUG
  {
    const std::size_t dispatcher_predecessors = transition_edges.size() + 1;
    const auto has_unique_incomings = [dispatcher_predecessors](const llvm::PHINode* phi) {
      if (phi->getNumIncomingValues() != dispatcher_predecessors) { return false; }
      llvm::DenseSet<const llvm::BasicBlock*> seen;
      for (unsigned index = 0; index < phi->getNumIncomingValues(); ++index) {
        if (!seen.insert(phi->getIncomingBlock(index)).second) { return false; }
      }
      return true;
    };
    assert(has_unique_incomings(state_phi) &&
           "state PHI must have exactly one incoming per dispatcher predecessor");
    for (const carried_value& carried : carried_values) {
      assert(has_unique_incomings(carried.dispatcher_phi) &&
             "dispatcher PHI must have exactly one incoming per dispatcher predecessor");
    }
  }
#endif

  // Break references before deleting. Every remaining use of an original PHI now
  // lives inside another original PHI (those operands were intentionally left
  // untouched by the use-replacement loop above), so route them all to the
  // dispatcher PHIs first. Dispatcher incomings were populated from the snapshot
  // and never reference an original PHI, so this cannot disturb the wiring. This
  // makes every erase order safe, including inter-referential / cyclic PHIs.
  for (llvm::PHINode* phi : original_phis) { phi->replaceAllUsesWith(dispatcher_phis[phi]); }

  for (llvm::PHINode* phi : original_phis) {
    assert(phi->use_empty() && "original PHI still has uses at erase time");
    phi->eraseFromParent();
  }

  std::vector<dispatch_case> dispatch_cases = build_dispatch_cases(blocks, state_ids, decoy_states);
  shuffle_dispatch_cases(dispatch_cases, state_rng);
  dispatch_tree_state tree_state;
  const dispatch_tree_context tree_context{
      .function = function,
      .state_value = state_phi,
      .default_target = blocks.front(),
      .mba_context = mba_context,
      .tree_state = tree_state,
  };
  emit_dispatch_subtree(
      *dispatch, tree_context, dispatch_cases, 0, flattening::block_role::root_dispatch);

  flattening::tag_function(function);

  return {.flattened = true,
          .state_count = analysis.state_count + decoy_states.size(),
          .conditional_branches = analysis.conditional_branches,
          .detail = std::to_string(analysis.state_count) + " state blocks flattened with " +
                    std::to_string(decoy_states.size()) + " decoy states"};
}

}  // namespace obf
