#include "obf/transforms/control_flattening.h"

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
#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
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
                             llvm::Function& function,
                             const mba::builder_context& base_context,
                             std::uint64_t salt,
                             std::uint32_t state_id) {
  mba::builder_context context = base_context;
  context.depth = std::max<std::uint32_t>(context.depth, 2);
  llvm::Value* encoded_state =
      mba::create_opaque_integer(builder,
                                 builder.getInt32Ty(),
                                 context,
                                 llvm::APInt(32, static_cast<std::uint64_t>(state_id)),
                                 salt,
                                 "obf.flat.state.opaque");
  llvm::Value* encoded_zero = mba::create_opaque_integer(builder,
                                                         builder.getInt32Ty(),
                                                         context,
                                                         llvm::APInt(32, 0),
                                                         salt ^ 0x9e3779b9ULL,
                                                         "obf.flat.state.zero");
  return mba::create_add(
      builder, encoded_state, encoded_zero, context, salt ^ 0xa55aa55aULL, "obf.flat.state.next");
}

llvm::Value* build_true_opaque_predicate(llvm::IRBuilder<>& builder,
                                          llvm::Function& function,
                                          std::uint32_t mba_depth,
                                          std::uint64_t salt_base) {
  return mba::build_entropy_true_predicate(builder,
                                           function,
                                           mba_depth,
                                           salt_base,
                                           0x31415926ULL,
                                           0x27182818ULL,
                                           "obf.flat.decoy.a",
                                           "obf.flat.decoy.b",
                                           "obf.flat.decoy.true");
}

llvm::BasicBlock* create_decoy_trap(llvm::Function& function,
                                    std::uint32_t mba_depth,
                                    std::uint64_t salt_base) {
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

  llvm::IRBuilder<> loop_builder(loop);
  llvm::PHINode* iteration =
      loop_builder.CreatePHI(loop_builder.getInt32Ty(), 2, "obf.flat.decoy.iter");
  llvm::PHINode* state =
      loop_builder.CreatePHI(loop_builder.getInt64Ty(), 2, "obf.flat.decoy.state");
  llvm::Value* rotl_shl = loop_builder.CreateShl(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 13), "obf.flat.decoy.rotl.shl");
  llvm::Value* rotl_lshr = loop_builder.CreateLShr(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 51), "obf.flat.decoy.rotl.lshr");
  llvm::Value* rotl = loop_builder.CreateOr(rotl_shl, rotl_lshr, "obf.flat.decoy.rotl");
  llvm::Value* mixed = loop_builder.CreateXor(
      rotl,
      llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x9e3779b97f4a7c15ULL),
      "obf.flat.decoy.mix");
  llvm::Value* multiplied = loop_builder.CreateMul(
      mixed,
      llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x94d049bb133111ebULL),
      "obf.flat.decoy.mul");
  llvm::Value* iteration64 =
      loop_builder.CreateZExt(iteration, loop_builder.getInt64Ty(), "obf.flat.decoy.iter64");
  llvm::Value* next_state =
      loop_builder.CreateXor(multiplied, iteration64, "obf.flat.decoy.state.next");
  llvm::Value* next_iteration = loop_builder.CreateAdd(
      iteration, llvm::ConstantInt::get(loop_builder.getInt32Ty(), 1), "obf.flat.decoy.iter.next");
  llvm::Value* predicate =
      build_true_opaque_predicate(loop_builder, function, mba_depth, salt_base + 0x71ULL);
  loop_builder.CreateCondBr(predicate, loop, trap);

  iteration->addIncoming(llvm::ConstantInt::get(loop_builder.getInt32Ty(), 0), entry);
  iteration->addIncoming(next_iteration, loop);
  state->addIncoming(initial_state, entry);
  state->addIncoming(next_state, loop);

  llvm::IRBuilder<> trap_builder(trap);
  trap_builder.CreateCall(llvm::Intrinsic::getOrInsertDeclaration(module, llvm::Intrinsic::trap));
  trap_builder.CreateUnreachable();
  return entry;
}

llvm::Value*
translate_value_for_edge(llvm::Value* value,
                         llvm::BasicBlock* source,
                         llvm::BasicBlock* successor,
                         const llvm::DenseMap<llvm::Value*, llvm::PHINode*>& dispatcher_phis) {
  if (auto* phi = llvm::dyn_cast<llvm::PHINode>(value)) {
    if (phi->getParent() == successor) {
      return translate_value_for_edge(
          phi->getIncomingValueForBlock(source), source, successor, dispatcher_phis);
    }

    if (const auto it = dispatcher_phis.find(phi); it != dispatcher_phis.end()) {
      return it->second;
    }

    return phi;
  }

  auto* instruction = llvm::dyn_cast<llvm::Instruction>(value);
  if (instruction == nullptr) { return value; }

  if (instruction->getParent() == source) { return instruction; }

  if (const auto it = dispatcher_phis.find(instruction); it != dispatcher_phis.end()) {
    return it->second;
  }

  return instruction;
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

std::vector<dispatch_case> build_dispatch_cases(
    llvm::ArrayRef<llvm::BasicBlock*> blocks,
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

std::string make_dispatch_block_name(llvm::StringRef role, std::size_t ordinal) {
  return ("obf.flat.dispatch." + role + std::to_string(ordinal)).str();
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

llvm::Value* materialize_dispatch_state_constant(llvm::IRBuilder<>& builder,
                                                 const mba::builder_context& mba_context,
                                                 std::uint32_t state_id,
                                                 std::uint64_t salt,
                                                 llvm::StringRef name) {
  return mba::create_opaque_integer(builder,
                                    builder.getInt32Ty(),
                                    mba_context,
                                    llvm::APInt(32, static_cast<std::uint64_t>(state_id)),
                                    salt,
                                    name);
}

void emit_dispatch_subtree(llvm::BasicBlock& block,
                           const dispatch_tree_context& context,
                           std::vector<dispatch_case> cases,
                           std::size_t depth);

void emit_dispatch_leaf(llvm::BasicBlock& block,
                        const dispatch_tree_context& context,
                        const dispatch_case& single_case,
                        std::size_t depth,
                        std::size_t ordinal) {
  llvm::IRBuilder<> builder(&block);
  llvm::Value* compare_state = materialize_dispatch_state_constant(
      builder,
      context.mba_context,
      single_case.state_id,
      build_dispatch_tree_salt(context.mba_context, depth, ordinal, 0x1f4a7101ULL),
      "obf.flat.dispatch.leaf.state");
  llvm::Value* is_match =
      builder.CreateICmpEQ(context.state_value, compare_state, "obf.flat.dispatch.eq");
  builder.CreateCondBr(is_match, single_case.target, context.default_target);
}

void emit_dispatch_subtree(llvm::BasicBlock& block,
                           const dispatch_tree_context& context,
                           std::vector<dispatch_case> cases,
                           std::size_t depth) {
  if (cases.empty()) {
    llvm::IRBuilder<> builder(&block);
    builder.CreateBr(context.default_target);
    return;
  }

  const std::size_t ordinal = context.tree_state.next_ordinal++;
  if (cases.size() == 1) {
    emit_dispatch_leaf(block, context, cases.front(), depth, ordinal);
    return;
  }

  std::vector<dispatch_case> ordered_cases = cases;
  std::sort(ordered_cases.begin(), ordered_cases.end(), [](const dispatch_case& lhs,
                                                           const dispatch_case& rhs) {
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

  llvm::BasicBlock* split_block = llvm::BasicBlock::Create(
      context.function.getContext(), make_dispatch_block_name("split", ordinal), &context.function);
  llvm::BasicBlock* left_entry = left_cases.empty()
                                     ? nullptr
                                     : llvm::BasicBlock::Create(context.function.getContext(),
                                                               make_dispatch_block_name("left", ordinal),
                                                               &context.function);
  llvm::BasicBlock* right_entry = right_cases.empty()
                                      ? nullptr
                                      : llvm::BasicBlock::Create(context.function.getContext(),
                                                                make_dispatch_block_name("right", ordinal),
                                                                &context.function);

  llvm::IRBuilder<> equality_builder(&block);
  llvm::Value* equality_state = materialize_dispatch_state_constant(
      equality_builder,
      context.mba_context,
      pivot.state_id,
      build_dispatch_tree_salt(context.mba_context, depth, ordinal, 0x1f4a7201ULL),
      "obf.flat.dispatch.node.eq.state");
  llvm::Value* is_equal =
      equality_builder.CreateICmpEQ(context.state_value, equality_state, "obf.flat.dispatch.eq");
  equality_builder.CreateCondBr(is_equal, pivot.target, split_block);

  llvm::IRBuilder<> split_builder(split_block);
  llvm::Value* magnitude_state = materialize_dispatch_state_constant(
      split_builder,
      context.mba_context,
      pivot.state_id,
      build_dispatch_tree_salt(context.mba_context, depth, ordinal, 0x1f4a7301ULL),
      "obf.flat.dispatch.node.ult.state");
  llvm::Value* is_less = split_builder.CreateICmpULT(
      context.state_value, magnitude_state, "obf.flat.dispatch.ult");
  split_builder.CreateCondBr(is_less,
                             left_entry != nullptr ? left_entry : context.default_target,
                             right_entry != nullptr ? right_entry : context.default_target);

  if (left_entry != nullptr) { emit_dispatch_subtree(*left_entry, context, left_cases, depth + 1); }
  if (right_entry != nullptr) {
    emit_dispatch_subtree(*right_entry, context, right_cases, depth + 1);
  }
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
    llvm::SmallVector<llvm::Use*, 8> escaping_uses;
    for (llvm::Use& use : carried.original->uses()) { escaping_uses.push_back(&use); }

    auto* instruction = llvm::cast<llvm::Instruction>(carried.original);
    for (llvm::Use* use : escaping_uses) {
      auto* user_instruction = llvm::dyn_cast<llvm::Instruction>(use->getUser());
      if (user_instruction == nullptr) {
        use->set(carried.dispatcher_phi);
        continue;
      }

      const bool replace_use = llvm::isa<llvm::PHINode>(instruction) ||
                               llvm::isa<llvm::PHINode>(user_instruction) ||
                               user_instruction->getParent() != instruction->getParent();
      if (replace_use) { use->set(carried.dispatcher_phi); }
    }
  }

  mba::builder_context mba_context =
      mba::get_or_create_builder_context(function, "obf.flat", 0x2f4d8f13ULL);
  mba_context.seed_base = mix_seed(mba_context.seed_base, options.seed);
  mba_context.depth = options.mba_depth;

  for (std::size_t decoy_index = 0; decoy_index < decoy_count; ++decoy_index) {
    llvm::BasicBlock* decoy_entry = create_decoy_trap(
        function,
        options.mba_depth,
        mix_seed(options.seed, static_cast<std::uint64_t>(decoy_index + 1)));
    if (decoy_entry == nullptr) { continue; }

    decoy_states.push_back(
        {.id = generate_sparse_state_id(state_rng, used_state_ids), .entry = decoy_entry});
  }

  std::vector<transition_edge> transition_edges;
  transition_edges.reserve(blocks.size() * 2);
  std::uint64_t transition_salt = 0x6137c4d9ULL;
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
      llvm::Value* next_state =
          encode_state_id(edge_builder,
                          function,
                          mba_context,
                          transition_salt + static_cast<std::uint64_t>(transition_edges.size() + 1),
                          state_ids[successor]);
      edge_builder.CreateBr(dispatch);
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
  state_phi->addIncoming(
      encode_state_id(
          setup_builder, function, mba_context, 0x13579bdfULL, state_ids[original_entry]),
      setup);
  for (const carried_value& carried : carried_values) {
    carried.dispatcher_phi->addIncoming(llvm::PoisonValue::get(carried.original->getType()), setup);
  }

  for (const transition_edge& edge : transition_edges) {
    state_phi->addIncoming(edge.next_state, edge.block);
    for (const carried_value& carried : carried_values) {
      carried.dispatcher_phi->addIncoming(
          translate_value_for_edge(carried.original, edge.source, edge.successor, dispatcher_phis),
          edge.block);
    }
  }

  for (llvm::PHINode* phi : original_phis) { phi->eraseFromParent(); }

  std::vector<dispatch_case> dispatch_cases =
      build_dispatch_cases(blocks, state_ids, decoy_states);
  shuffle_dispatch_cases(dispatch_cases, state_rng);
  dispatch_tree_state tree_state;
  const dispatch_tree_context tree_context{
      .function = function,
      .state_value = state_phi,
      .default_target = blocks.front(),
      .mba_context = mba_context,
      .tree_state = tree_state,
  };
  emit_dispatch_subtree(*dispatch, tree_context, dispatch_cases, 0);

  return {.flattened = true,
          .state_count = analysis.state_count + decoy_states.size(),
          .conditional_branches = analysis.conditional_branches,
          .detail = std::to_string(analysis.state_count) + " state blocks flattened with " +
                    std::to_string(decoy_states.size()) + " decoy states"};
}

}  // namespace obf
