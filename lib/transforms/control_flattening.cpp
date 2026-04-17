#include "obf/transforms/control_flattening.h"

#include "obf/transforms/mba.h"

#include "llvm/ADT/Hashing.h"
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

constexpr llvm::StringRef kCfgStatePlaceholderName = "__obf_get_cfg_state";
constexpr llvm::StringRef kExpectedCfgStatePlaceholderName =
    "__obf_get_expected_cfg_state";

struct carried_value {
  llvm::Value *original = nullptr;
  llvm::PHINode *dispatcher_phi = nullptr;
};

struct transition_edge {
  llvm::BasicBlock *source = nullptr;
  llvm::BasicBlock *successor = nullptr;
  llvm::BasicBlock *block = nullptr;
  llvm::Value *next_state = nullptr;
};

struct decoy_state {
  std::uint32_t id = 0;
  llvm::BasicBlock *entry = nullptr;
};

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

std::mt19937 build_state_rng(const llvm::Function &function,
                            const control_flattening_options &options) {
  const std::uint64_t seed_base =
      options.seed == 0 ? 0x6d2534f1f6c7a29bULL : options.seed;
  const std::uint64_t mixed_seed =
      mix_seed(seed_base,
               static_cast<std::uint64_t>(llvm::hash_value(function.getName())));
  std::seed_seq seed_words{
      static_cast<std::uint32_t>(mixed_seed),
      static_cast<std::uint32_t>(mixed_seed >> 32),
      static_cast<std::uint32_t>(function.arg_size()),
      static_cast<std::uint32_t>(function.size())};
  return std::mt19937(seed_words);
}

std::uint32_t generate_sparse_state_id(std::mt19937 &rng,
                                       llvm::DenseSet<std::uint32_t> &used_ids) {
  while (true) {
    std::uint32_t candidate = rng();
    candidate |= 0x01010101U;
    if (candidate == 0 || !used_ids.insert(candidate).second) {
      continue;
    }

    return candidate;
  }
}

std::size_t choose_decoy_count(std::size_t block_count,
                               const control_flattening_options &options) {
  if (options.max_decoy_states == 0 || block_count == 0) {
    return 0;
  }

  return std::min<std::size_t>(options.max_decoy_states,
                               std::max<std::size_t>(1, block_count / 2));
}

bool instruction_escapes_block(const llvm::Instruction &instruction) {
  for (const llvm::User *user : instruction.users()) {
    const auto *user_instruction = llvm::dyn_cast<llvm::Instruction>(user);
    if (user_instruction == nullptr) {
      return true;
    }

    if (user_instruction->getParent() != instruction.getParent() ||
        llvm::isa<llvm::PHINode>(user_instruction)) {
      return true;
    }
  }

  return false;
}

bool has_supported_terminators_only(const llvm::Function &function,
                                    std::size_t &conditional_branches) {
  conditional_branches = 0;

  for (const llvm::BasicBlock &block : function) {
    const llvm::Instruction *terminator = block.getTerminator();
    if (terminator == nullptr) {
      return false;
    }

    if (llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    if (const auto *branch = llvm::dyn_cast<llvm::BranchInst>(terminator)) {
      if (branch->isConditional()) {
        ++conditional_branches;
      }
      continue;
    }

    return false;
  }

  return true;
}

void hoist_entry_allocas_to_setup(llvm::BasicBlock &entry,
                                  llvm::BasicBlock &setup) {
  llvm::Instruction *insert_before = setup.getTerminator();
  llvm::SmallVector<llvm::AllocaInst *, 8> allocas;

  for (llvm::Instruction &instruction : entry) {
    auto *alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
    if (alloca == nullptr) {
      break;
    }

    allocas.push_back(alloca);
  }

  for (llvm::AllocaInst *alloca : allocas) {
    alloca->moveBefore(insert_before->getIterator());
  }
}

llvm::Value *encode_state_id(llvm::IRBuilder<> &builder, llvm::Function &function,
                             const mba::builder_context &base_context,
                             std::uint64_t salt, std::uint32_t state_id) {
  mba::builder_context context = base_context;
  context.depth = std::max<std::uint32_t>(context.depth, 2);
  llvm::Value *encoded_state = mba::create_opaque_integer(
      builder, builder.getInt32Ty(), context,
      llvm::APInt(32, static_cast<std::uint64_t>(state_id)), salt,
      "obf.flat.state.opaque");
  llvm::Value *encoded_zero = mba::create_opaque_integer(
      builder, builder.getInt32Ty(), context, llvm::APInt(32, 0),
      salt ^ 0x9e3779b9ULL, "obf.flat.state.zero");
  return mba::create_add(builder, encoded_state, encoded_zero, context,
                         salt ^ 0xa55aa55aULL, "obf.flat.state.next");
}

llvm::Value *build_true_opaque_predicate(llvm::IRBuilder<> &builder,
                                         llvm::Function &function,
                                         llvm::Value *state_value,
                                         const mba::builder_context &base_context,
                                         std::uint64_t salt_base) {
  mba::builder_context context_a = base_context;
  mba::builder_context context_b = base_context;
  context_a.depth = std::max<std::uint32_t>(context_a.depth, 2);
  context_b.depth = std::max<std::uint32_t>(context_b.depth, 2);
  context_a.seed_base = mix_seed(context_a.seed_base, salt_base ^ 0x31415926ULL);
  context_b.seed_base = mix_seed(context_b.seed_base, salt_base ^ 0x27182818ULL);

  llvm::Value *seed_a = mba::entangle_value(
      builder, state_value, context_a, salt_base + 0x11ULL, "obf.flat.decoy.seed.a");
  llvm::Value *zero_a = mba::create_opaque_integer(
      builder, builder.getInt64Ty(), context_a, llvm::APInt(64, 0),
      salt_base + 0x21ULL, "obf.flat.decoy.zero.a");
  llvm::Value *expr_a = mba::create_add(builder, seed_a, zero_a, context_a,
                                        salt_base + 0x31ULL,
                                        "obf.flat.decoy.expr.a");

  llvm::Value *seed_b = mba::entangle_value(
      builder, state_value, context_b, salt_base + 0x41ULL, "obf.flat.decoy.seed.b");
  llvm::Value *zero_b = mba::create_opaque_integer(
      builder, builder.getInt64Ty(), context_b, llvm::APInt(64, 0),
      salt_base + 0x51ULL, "obf.flat.decoy.zero.b");
  llvm::Value *expr_b = mba::create_xor(builder, seed_b, zero_b, context_b,
                                        salt_base + 0x61ULL,
                                        "obf.flat.decoy.expr.b");
  return builder.CreateICmpEQ(expr_a, expr_b, "obf.flat.decoy.true");
}

llvm::BasicBlock *create_decoy_trap(llvm::Function &function,
                                    const mba::builder_context &base_context,
                                    std::uint64_t salt_base) {
  llvm::Module *module = function.getParent();
  if (module == nullptr) {
    return nullptr;
  }

  llvm::LLVMContext &context = function.getContext();
  llvm::BasicBlock *entry = llvm::BasicBlock::Create(context, "obf.flat.decoy",
                                                     &function);
  llvm::BasicBlock *loop = llvm::BasicBlock::Create(context, "obf.flat.decoy.loop",
                                                    &function);
  llvm::BasicBlock *trap = llvm::BasicBlock::Create(context, "obf.flat.decoy.trap",
                                                    &function);

  llvm::IRBuilder<> entry_builder(entry);
  llvm::Value *entropy = entry_builder.CreateLoad(
      entry_builder.getInt64Ty(), mba::get_or_create_entropy_anchor(*module),
      "obf.flat.decoy.entropy");
  llvm::Value *initial_state = entry_builder.CreateXor(
      entropy,
      llvm::ConstantInt::get(entry_builder.getInt64Ty(),
                             mix_seed(salt_base, 0xd6e8feb86659fd93ULL)),
      "obf.flat.decoy.state.init");
  entry_builder.CreateBr(loop);

  llvm::IRBuilder<> loop_builder(loop);
  llvm::PHINode *iteration =
      loop_builder.CreatePHI(loop_builder.getInt32Ty(), 2, "obf.flat.decoy.iter");
  llvm::PHINode *state =
      loop_builder.CreatePHI(loop_builder.getInt64Ty(), 2, "obf.flat.decoy.state");
  llvm::Value *rotl_shl = loop_builder.CreateShl(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 13),
      "obf.flat.decoy.rotl.shl");
  llvm::Value *rotl_lshr = loop_builder.CreateLShr(
      state, llvm::ConstantInt::get(loop_builder.getInt64Ty(), 51),
      "obf.flat.decoy.rotl.lshr");
  llvm::Value *rotl =
      loop_builder.CreateOr(rotl_shl, rotl_lshr, "obf.flat.decoy.rotl");
  llvm::Value *mixed = loop_builder.CreateXor(
      rotl,
      llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x9e3779b97f4a7c15ULL),
      "obf.flat.decoy.mix");
  llvm::Value *multiplied = loop_builder.CreateMul(
      mixed,
      llvm::ConstantInt::get(loop_builder.getInt64Ty(), 0x94d049bb133111ebULL),
      "obf.flat.decoy.mul");
  llvm::Value *iteration64 = loop_builder.CreateZExt(
      iteration, loop_builder.getInt64Ty(), "obf.flat.decoy.iter64");
  llvm::Value *next_state = loop_builder.CreateXor(
      multiplied, iteration64, "obf.flat.decoy.state.next");
  llvm::Value *next_iteration = loop_builder.CreateAdd(
      iteration, llvm::ConstantInt::get(loop_builder.getInt32Ty(), 1),
      "obf.flat.decoy.iter.next");
  llvm::Value *predicate = build_true_opaque_predicate(
      loop_builder, function, next_state, base_context, salt_base + 0x71ULL);
  loop_builder.CreateCondBr(predicate, loop, trap);

  iteration->addIncoming(llvm::ConstantInt::get(loop_builder.getInt32Ty(), 0),
                         entry);
  iteration->addIncoming(next_iteration, loop);
  state->addIncoming(initial_state, entry);
  state->addIncoming(next_state, loop);

  llvm::IRBuilder<> trap_builder(trap);
  trap_builder.CreateCall(
      llvm::Intrinsic::getOrInsertDeclaration(module, llvm::Intrinsic::trap));
  trap_builder.CreateUnreachable();
  return entry;
}

llvm::Value *translate_value_for_edge(
    llvm::Value *value, llvm::BasicBlock *source, llvm::BasicBlock *successor,
    const llvm::DenseMap<llvm::Value *, llvm::PHINode *> &dispatcher_phis) {
  if (auto *phi = llvm::dyn_cast<llvm::PHINode>(value)) {
    if (phi->getParent() == successor) {
      return translate_value_for_edge(phi->getIncomingValueForBlock(source), source,
                                      successor, dispatcher_phis);
    }

    if (const auto it = dispatcher_phis.find(phi); it != dispatcher_phis.end()) {
      return it->second;
    }

    return phi;
  }

  auto *instruction = llvm::dyn_cast<llvm::Instruction>(value);
  if (instruction == nullptr) {
    return value;
  }

  if (instruction->getParent() == source) {
    return instruction;
  }

  if (const auto it = dispatcher_phis.find(instruction);
      it != dispatcher_phis.end()) {
    return it->second;
  }

  return instruction;
}

bool is_cfg_state_placeholder_call(const llvm::Instruction &instruction,
                                   llvm::StringRef expected_name) {
  const auto *call = llvm::dyn_cast<llvm::CallInst>(&instruction);
  if (call == nullptr) {
    return false;
  }

  const llvm::Function *callee = call->getCalledFunction();
  return callee != nullptr && callee->getName() == expected_name;
}

void bind_cfg_state_placeholders(
    llvm::ArrayRef<llvm::BasicBlock *> blocks,
    const llvm::DenseMap<llvm::BasicBlock *, std::uint32_t> &state_ids,
    llvm::PHINode *state_phi) {
  if (state_phi == nullptr) {
    return;
  }

  llvm::Type *state_type = state_phi->getType();
  for (llvm::BasicBlock *block : blocks) {
    if (block == nullptr) {
      continue;
    }

    llvm::SmallVector<llvm::Instruction *, 4> erase_list;
    for (llvm::Instruction &instruction : *block) {
      if (is_cfg_state_placeholder_call(instruction, kCfgStatePlaceholderName)) {
        instruction.replaceAllUsesWith(state_phi);
        erase_list.push_back(&instruction);
        continue;
      }

      if (is_cfg_state_placeholder_call(instruction,
                                        kExpectedCfgStatePlaceholderName)) {
        instruction.replaceAllUsesWith(llvm::ConstantInt::get(
            state_type, static_cast<std::uint64_t>(state_ids.lookup(block))));
        erase_list.push_back(&instruction);
      }
    }

    for (llvm::Instruction *instruction : erase_list) {
      instruction->eraseFromParent();
    }
  }
}

} // namespace

control_flattening_result
analyze_control_flattening(const llvm::Function &function,
                           const control_flattening_options &options) {
  if (function.isDeclaration()) {
    return {.flattened = false, .detail = "declaration"};
  }

  if (function.size() < options.min_blocks) {
    return {.flattened = false, .detail = "too few basic blocks"};
  }

  if (function.size() > options.max_blocks) {
    return {.flattened = false, .detail = "too many basic blocks"};
  }

  std::size_t instruction_count = 0;
  for (const llvm::BasicBlock &block : function) {
    if (block.isEHPad()) {
      return {.flattened = false, .detail = "contains EH pad"};
    }

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

control_flattening_result
run_control_flattening(llvm::Function &function,
                       const control_flattening_options &options) {
  const control_flattening_result analysis =
      analyze_control_flattening(function, options);
  if (!analysis.flattened) {
    return analysis;
  }

  llvm::BasicBlock *original_entry = &function.getEntryBlock();
  llvm::LLVMContext &context = function.getContext();
  llvm::BasicBlock *setup =
      llvm::BasicBlock::Create(context, "obf.flat.setup", &function, original_entry);
  llvm::BasicBlock *dispatch = llvm::BasicBlock::Create(
      context, "obf.flat.dispatch", &function, original_entry);
  llvm::IRBuilder<> setup_builder(setup);
  setup_builder.CreateBr(dispatch);
  hoist_entry_allocas_to_setup(*original_entry, *setup);

  std::vector<llvm::BasicBlock *> blocks;
  blocks.reserve(function.size());
  for (llvm::BasicBlock &block : function) {
    if (&block != setup && &block != dispatch) {
      blocks.push_back(&block);
    }
  }

  std::mt19937 state_rng = build_state_rng(function, options);
  llvm::DenseSet<std::uint32_t> used_state_ids;
  llvm::DenseMap<llvm::BasicBlock *, std::uint32_t> state_ids;
  for (llvm::BasicBlock *block : blocks) {
    state_ids[block] = generate_sparse_state_id(state_rng, used_state_ids);
  }

  const std::size_t decoy_count = choose_decoy_count(blocks.size(), options);
  std::vector<decoy_state> decoy_states;
  decoy_states.reserve(decoy_count);

  std::vector<carried_value> carried_values;
  carried_values.reserve(blocks.size());
  std::vector<llvm::PHINode *> original_phis;
  for (llvm::BasicBlock *block : blocks) {
    for (llvm::Instruction &instruction : *block) {
      if (auto *phi = llvm::dyn_cast<llvm::PHINode>(&instruction)) {
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

  llvm::PHINode *state_phi = llvm::PHINode::Create(
      llvm::Type::getInt32Ty(context), 1, "obf.state", dispatch);
  llvm::DenseMap<llvm::Value *, llvm::PHINode *> dispatcher_phis;
  for (carried_value &carried : carried_values) {
    auto *phi = llvm::PHINode::Create(carried.original->getType(), 1,
                                      "obf.flat.val", dispatch);
    carried.dispatcher_phi = phi;
    dispatcher_phis[carried.original] = phi;
  }

  bind_cfg_state_placeholders(blocks, state_ids, state_phi);

  for (const carried_value &carried : carried_values) {
    llvm::SmallVector<llvm::Use *, 8> escaping_uses;
    for (llvm::Use &use : carried.original->uses()) {
      escaping_uses.push_back(&use);
    }

    auto *instruction = llvm::cast<llvm::Instruction>(carried.original);
    for (llvm::Use *use : escaping_uses) {
      auto *user_instruction = llvm::dyn_cast<llvm::Instruction>(use->getUser());
      if (user_instruction == nullptr) {
        use->set(carried.dispatcher_phi);
        continue;
      }

      const bool replace_use = llvm::isa<llvm::PHINode>(instruction) ||
                               llvm::isa<llvm::PHINode>(user_instruction) ||
                               user_instruction->getParent() != instruction->getParent();
      if (replace_use) {
        use->set(carried.dispatcher_phi);
      }
    }
  }

  mba::builder_context mba_context =
      mba::get_or_create_builder_context(function, "obf.flat", 0x2f4d8f13ULL);
  mba_context.seed_base = mix_seed(mba_context.seed_base, options.seed);

  for (std::size_t decoy_index = 0; decoy_index < decoy_count; ++decoy_index) {
    llvm::BasicBlock *decoy_entry = create_decoy_trap(
        function, mba_context,
        mix_seed(options.seed, static_cast<std::uint64_t>(decoy_index + 1)));
    if (decoy_entry == nullptr) {
      continue;
    }

    decoy_states.push_back({.id = generate_sparse_state_id(state_rng, used_state_ids),
                            .entry = decoy_entry});
  }

  std::vector<transition_edge> transition_edges;
  transition_edges.reserve(blocks.size() * 2);
  std::uint64_t transition_salt = 0x6137c4d9ULL;
  for (llvm::BasicBlock *block : blocks) {
    llvm::Instruction *terminator = block->getTerminator();
    if (llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    auto *branch = llvm::cast<llvm::BranchInst>(terminator);
    llvm::SmallVector<transition_edge, 2> block_edges;
    for (unsigned successor_index = 0; successor_index < branch->getNumSuccessors();
         ++successor_index) {
      llvm::BasicBlock *successor = branch->getSuccessor(successor_index);
      llvm::BasicBlock *edge_block = llvm::BasicBlock::Create(
          context, "obf.flat.edge", &function, dispatch);
      llvm::IRBuilder<> edge_builder(edge_block);
      llvm::Value *next_state = encode_state_id(
          edge_builder, function, mba_context,
          transition_salt + static_cast<std::uint64_t>(transition_edges.size() + 1),
          state_ids[successor]);
      edge_builder.CreateBr(dispatch);
      block_edges.push_back({.source = block,
                             .successor = successor,
                             .block = edge_block,
                             .next_state = next_state});
    }

    llvm::IRBuilder<> builder(branch);
    if (branch->isConditional()) {
      builder.CreateCondBr(branch->getCondition(), block_edges[0].block,
                           block_edges[1].block);
    } else {
      builder.CreateBr(block_edges[0].block);
    }
    branch->eraseFromParent();

    transition_edges.insert(transition_edges.end(), block_edges.begin(),
                            block_edges.end());
  }

  setup_builder.SetInsertPoint(setup->getTerminator());
  state_phi->addIncoming(encode_state_id(setup_builder, function, mba_context,
                                         0x13579bdfULL,
                                         state_ids[original_entry]),
                         setup);
  for (const carried_value &carried : carried_values) {
    carried.dispatcher_phi->addIncoming(llvm::PoisonValue::get(carried.original->getType()),
                                        setup);
  }

  for (const transition_edge &edge : transition_edges) {
    state_phi->addIncoming(edge.next_state, edge.block);
    for (const carried_value &carried : carried_values) {
      carried.dispatcher_phi->addIncoming(
          translate_value_for_edge(carried.original, edge.source, edge.successor,
                                   dispatcher_phis),
          edge.block);
    }
  }

  for (llvm::PHINode *phi : original_phis) {
    phi->eraseFromParent();
  }

  llvm::IRBuilder<> dispatch_builder(dispatch);
  llvm::SwitchInst *switch_inst =
      dispatch_builder.CreateSwitch(state_phi, blocks.front(),
                                    blocks.size() + decoy_states.size());
  for (llvm::BasicBlock *block : blocks) {
    switch_inst->addCase(llvm::ConstantInt::get(llvm::Type::getInt32Ty(context),
                                                state_ids.lookup(block)),
                         block);
  }
  for (const decoy_state &decoy : decoy_states) {
    if (decoy.entry == nullptr) {
      continue;
    }

    switch_inst->addCase(
        llvm::ConstantInt::get(llvm::Type::getInt32Ty(context), decoy.id),
        decoy.entry);
  }

  return {.flattened = true,
          .state_count = analysis.state_count + decoy_states.size(),
          .conditional_branches = analysis.conditional_branches,
          .detail = std::to_string(analysis.state_count) +
                    " state blocks flattened with " +
                    std::to_string(decoy_states.size()) + " decoy states"};
}

} // namespace obf
