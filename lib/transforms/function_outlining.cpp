#include "obf/transforms/function_outlining.h"

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace obf {

namespace {

struct handler_info {
  llvm::BasicBlock *block = nullptr;
  llvm::SmallVector<llvm::ConstantInt *, 2> states;
  std::uint64_t rank = 0;
};

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

bool is_terminal_handler(const llvm::BasicBlock &block) {
  const llvm::Instruction *terminator = block.getTerminator();
  return llvm::isa<llvm::ReturnInst>(terminator) ||
         llvm::isa<llvm::UnreachableInst>(terminator);
}

llvm::SwitchInst *find_flatten_dispatch(llvm::Function &function) {
  for (llvm::BasicBlock &block : function) {
    if (!block.getName().starts_with("obf.flat.dispatch")) {
      continue;
    }

    if (auto *switch_inst = llvm::dyn_cast<llvm::SwitchInst>(block.getTerminator())) {
      return switch_inst;
    }
  }

  return nullptr;
}

std::vector<handler_info> collect_handler_infos(llvm::Function &function,
                                                std::uint64_t seed) {
  llvm::SwitchInst *dispatch = find_flatten_dispatch(function);
  if (dispatch == nullptr) {
    return {};
  }

  llvm::DenseMap<llvm::BasicBlock *, std::size_t> indices;
  std::vector<handler_info> handlers;
  llvm::BasicBlock *entry_handler = dispatch->getDefaultDest();

  for (auto case_handle : dispatch->cases()) {
    llvm::BasicBlock *handler = case_handle.getCaseSuccessor();
    if (handler == nullptr || handler == entry_handler ||
        handler == dispatch->getParent() || is_terminal_handler(*handler) ||
        handler->getName().starts_with("obf.flat.edge") ||
        handler->getName().starts_with("obf.flat.decoy")) {
      continue;
    }

    const auto [iterator, inserted] =
        indices.try_emplace(handler, handlers.size());
    if (inserted) {
      handlers.push_back({.block = handler});
    }

    handlers[iterator->second].states.push_back(case_handle.getCaseValue());
  }

  for (handler_info &handler : handlers) {
    handler.rank = mix_seed(
        seed == 0 ? 0x6d2534f1f6c7a29bULL : seed,
        stable_hash_string(handler.block->getName()));
  }

  std::sort(handlers.begin(), handlers.end(), [](const handler_info &lhs,
                                                 const handler_info &rhs) {
    return lhs.rank < rhs.rank;
  });
  return handlers;
}

std::size_t choose_cluster_size(std::size_t remaining,
                                const function_outlining_options &options,
                                std::uint64_t salt) {
  const std::size_t min_size = std::max<std::size_t>(1, options.min_cluster_size);
  const std::size_t max_size = std::max(min_size, options.max_cluster_size);
  if (remaining < min_size) {
    return 0;
  }

  if (remaining <= max_size) {
    return remaining;
  }

  std::size_t chosen =
      min_size + (mix_seed(options.seed, salt) % (max_size - min_size + 1));
  if (remaining - chosen < min_size) {
    chosen = remaining - min_size;
  }

  return std::clamp(chosen, min_size, max_size);
}

std::string build_shard_name(std::uint64_t seed, std::uint64_t index) {
  return "__obf_shard_" +
         llvm::utohexstr(mix_seed(seed == 0 ? 0xbadc0ffee0ddf00dULL : seed,
                                  index + 1),
                         /*LowerCase=*/true);
}

void obfuscate_shard_calls(llvm::Function &parent, llvm::Function &shard,
                           const function_outlining_options &options,
                           std::uint64_t salt_base) {
  mba::builder_context context =
      mba::get_or_create_builder_context(parent, "obf.shard.call",
                                         mix_seed(options.seed, salt_base));
  context.depth = options.mba_depth;

  std::uint64_t local_salt = salt_base;
  llvm::SmallVector<llvm::CallBase *, 4> calls;
  for (llvm::User *user : shard.users()) {
    auto *call = llvm::dyn_cast<llvm::CallBase>(user);
    if (call != nullptr && call->getFunction() == &parent &&
        call->getCalledOperand() == &shard) {
      calls.push_back(call);
    }
  }

  for (llvm::CallBase *call : calls) {
    llvm::IRBuilder<> builder(call);
    llvm::Value *base = llvm::CastInst::Create(
        llvm::Instruction::PtrToInt, &shard, builder.getInt64Ty(),
        "obf.shard.addr.base", call->getIterator());
    llvm::Value *zero = mba::create_opaque_integer(
        builder, builder.getInt64Ty(), context, llvm::APInt(64, 0),
        local_salt + 0x11ULL, "obf.shard.addr.zero");
    llvm::Value *address = mba::create_add(builder, base, zero, context,
                                           local_salt + 0x21ULL,
                                           "obf.shard.addr");
    llvm::Value *indirect = builder.CreateIntToPtr(
        address, call->getCalledOperand()->getType(), "obf.shard.indirect");
    call->setCalledOperand(indirect);
    ++local_salt;
  }
}

bool try_extract_cluster(llvm::Function &function, llvm::SwitchInst &dispatch,
                         llvm::ArrayRef<handler_info> cluster_handlers,
                         const function_outlining_options &options,
                         llvm::CodeExtractorAnalysisCache &cache,
                         llvm::DominatorTree &dom_tree,
                         llvm::AssumptionCache &assumption_cache,
                         std::uint64_t cluster_index,
                         llvm::SmallVectorImpl<llvm::Function *> &shards) {
  if (cluster_handlers.size() < options.min_cluster_size) {
    return false;
  }

  llvm::LLVMContext &context = function.getContext();
  llvm::BasicBlock *cluster_entry = llvm::BasicBlock::Create(
      context, "obf.outline.entry", &function, cluster_handlers.front().block);
  llvm::IRBuilder<> entry_builder(cluster_entry);
  llvm::SwitchInst *cluster_switch = entry_builder.CreateSwitch(
      dispatch.getCondition(), cluster_handlers.front().block,
      cluster_handlers.size());

  auto restore_dispatch_cases = [&]() {
    for (auto case_handle : dispatch.cases()) {
      for (const handler_info &handler : cluster_handlers) {
        if (llvm::is_contained(handler.states, case_handle.getCaseValue())) {
          case_handle.setSuccessor(handler.block);
        }
      }
    }
  };

  llvm::SmallVector<llvm::BasicBlock *, 8> region_blocks;
  region_blocks.push_back(cluster_entry);
  for (const handler_info &handler : cluster_handlers) {
    region_blocks.push_back(handler.block);
    for (llvm::ConstantInt *state : handler.states) {
      cluster_switch->addCase(state, handler.block);
      for (auto case_handle : dispatch.cases()) {
        if (case_handle.getCaseValue() == state) {
          case_handle.setSuccessor(cluster_entry);
        }
      }
    }
  }

  dom_tree.recalculate(function);
  llvm::CodeExtractor extractor(region_blocks, &dom_tree,
                                /*AggregateArgs=*/false,
                                /*BFI=*/nullptr, /*BPI=*/nullptr,
                                &assumption_cache,
                                /*AllowVarArgs=*/false,
                                /*AllowAlloca=*/false,
                                /*AllocationBlock=*/nullptr,
                                build_shard_name(options.seed, cluster_index));
  if (!extractor.isEligible()) {
    restore_dispatch_cases();
    cluster_entry->eraseFromParent();
    dom_tree.recalculate(function);
    return false;
  }

  llvm::Function *shard = extractor.extractCodeRegion(cache);
  if (shard == nullptr) {
    restore_dispatch_cases();
    if (cluster_entry->getParent() != nullptr) {
      cluster_entry->eraseFromParent();
    }
    dom_tree.recalculate(function);
    return false;
  }

  shard->setName(build_shard_name(options.seed, cluster_index));
  shard->setLinkage(llvm::GlobalValue::InternalLinkage);
  shard->setDSOLocal(true);
  obfuscate_shard_calls(function, *shard, options, cluster_index + 1);
  dom_tree.recalculate(function);
  shards.push_back(shard);
  return true;
}

function_outlining_result analyze_impl(const llvm::Function &function,
                                       const function_outlining_options &options) {
  if (function.isDeclaration()) {
    return {.shard_count = 0, .detail = "declaration"};
  }

  llvm::Function &mutable_function = const_cast<llvm::Function &>(function);
  const std::vector<handler_info> handlers =
      collect_handler_infos(mutable_function, options.seed);
  if (handlers.empty()) {
    return {.shard_count = 0, .detail = "not a flattened handler graph"};
  }

  const std::size_t min_cluster_size =
      std::max<std::size_t>(1, options.min_cluster_size);
  const std::size_t possible = handlers.size() / min_cluster_size;
  if (possible == 0) {
    return {.shard_count = 0,
            .detail = "not enough flattened handlers to outline"};
  }

  return {.shard_count = possible,
          .detail = std::to_string(possible) + " shard cluster(s) available"};
}

} // namespace

function_outlining_result
analyze_function_outlining(const llvm::Function &function,
                           const function_outlining_options &options) {
  return analyze_impl(function, options);
}

function_outlining_result
run_function_outlining(llvm::Function &function,
                       const function_outlining_options &options) {
  const function_outlining_result analysis = analyze_impl(function, options);
  if (analysis.shard_count == 0) {
    return analysis;
  }

  llvm::SwitchInst *dispatch = find_flatten_dispatch(function);
  if (dispatch == nullptr) {
    return {.shard_count = 0, .detail = "flattened dispatcher not found"};
  }

  std::vector<handler_info> handlers = collect_handler_infos(function, options.seed);
  if (handlers.size() < options.min_cluster_size) {
    return {.shard_count = 0,
            .detail = "not enough flattened handlers to outline"};
  }

  llvm::CodeExtractorAnalysisCache cache(function);
  llvm::DominatorTree dom_tree(function);
  llvm::LoopInfo loop_info(dom_tree);
  llvm::AssumptionCache assumption_cache(function);
  (void)loop_info;
  llvm::SmallVector<llvm::Function *, 8> shards;

  std::size_t index = 0;
  std::uint64_t cluster_index = 0;
  while (index < handlers.size()) {
    const std::size_t remaining = handlers.size() - index;
    const std::size_t preferred =
        choose_cluster_size(remaining, options, cluster_index + 1);
    if (preferred < options.min_cluster_size) {
      break;
    }

    bool extracted = false;
    for (std::size_t cluster_size = preferred;
         cluster_size >= options.min_cluster_size; --cluster_size) {
      if (index + cluster_size > handlers.size()) {
        continue;
      }

      extracted = try_extract_cluster(function, *dispatch,
                                      llvm::ArrayRef(handlers).slice(index,
                                                                     cluster_size),
                                      options, cache, dom_tree,
                                      assumption_cache, cluster_index, shards);
      if (extracted) {
        index += cluster_size;
        loop_info = llvm::LoopInfo(dom_tree);
        break;
      }

      if (cluster_size == options.min_cluster_size) {
        break;
      }
    }

    if (!extracted) {
      ++index;
    }
    ++cluster_index;
  }

  if (shards.empty()) {
    return {.shard_count = 0,
            .detail = "no flattened handler clusters could be outlined"};
  }

  return {.shard_count = shards.size(),
          .detail = std::to_string(shards.size()) + " shard function(s) created"};
}

} // namespace obf
