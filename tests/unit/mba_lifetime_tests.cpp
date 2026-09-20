#include "obf/transforms/mba.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#include <atomic>
#include <barrier>
#include <cstddef>
#include <iostream>
#include <new>
#include <thread>
#include <vector>

namespace {

int g_failures = 0;

void Fail(const char* message) {
  ++g_failures;
  std::cerr << "[fail] " << message << '\n';
}

void ExpectTrue(bool condition, const char* message) {
  if (!condition) { Fail(message); }
}

void ExpectSizeEq(std::size_t actual, std::size_t expected, const char* message) {
  if (actual == expected) { return; }

  ++g_failures;
  std::cerr << "[fail] " << message << " actual=" << actual << " expected=" << expected << '\n';
}

std::size_t TotalShapes(const obf::mba::mba_shape_counts& counts) {
  return counts.linear_count + counts.affine_count + counts.polynomial_count + counts.mul_count;
}

llvm::Function* CreateTestFunction(llvm::Module& module, llvm::StringRef name) {
  auto* function_type = llvm::FunctionType::get(llvm::Type::getInt32Ty(module.getContext()), false);
  return llvm::Function::Create(function_type, llvm::GlobalValue::InternalLinkage, name, module);
}

void EmitSingleAdd(llvm::Function& function, const obf::mba::builder_context& context) {
  auto* entry = llvm::BasicBlock::Create(function.getContext(), "entry", &function);
  llvm::IRBuilder<> builder(entry);
  llvm::Value* result = obf::mba::create_add(
      builder, builder.getInt32(5), builder.getInt32(7), context, 0x51ULL, "obf.mba.test");
  builder.CreateRet(result);
  ExpectTrue(!llvm::verifyFunction(function), "test MBA function must verify");
}

llvm::Value* EmitAddChain(llvm::IRBuilder<>& builder,
                          llvm::Value* value,
                          const obf::mba::builder_context& context,
                          std::uint64_t salt_base,
                          int steps,
                          llvm::StringRef name = "obf.mba.chain") {
  for (int step = 0; step < steps; ++step) {
    value = obf::mba::create_add(builder,
                                 value,
                                 builder.getInt32(step + 1),
                                 context,
                                 salt_base + static_cast<std::uint64_t>(step),
                                 name);
  }
  return value;
}

void TestModuleClearPreservesLiveBuilderContexts() {
  obf::mba::clear_mba_counters();

  llvm::LLVMContext context;
  llvm::Module module("mba.clear", context);
  llvm::Function* function = CreateTestFunction(module, "tracked");
  obf::mba::builder_context builder_context =
      obf::mba::get_or_create_builder_context(*function, "clear", 0x3456ULL);
  builder_context.depth = 1;

  auto* entry = llvm::BasicBlock::Create(context, "entry", function);
  auto* tail = llvm::BasicBlock::Create(context, "tail", function);

  llvm::IRBuilder<> entry_builder(entry);
  obf::mba::create_add(entry_builder,
                       entry_builder.getInt32(1),
                       entry_builder.getInt32(2),
                       builder_context,
                       0x61ULL);
  entry_builder.CreateBr(tail);

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*function)),
               1,
               "initial counters must be visible before module clear");

  obf::mba::clear_mba_counters(&module);

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*function)),
               0,
               "module clear must reset visible MBA counters");

  llvm::IRBuilder<> tail_builder(tail);
  llvm::Value* result = obf::mba::create_add(
      tail_builder, tail_builder.getInt32(3), tail_builder.getInt32(4), builder_context, 0x63ULL);
  tail_builder.CreateRet(result);

  ExpectTrue(!llvm::verifyFunction(*function), "cleared MBA function must verify");
  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*function)),
               1,
               "module clear must preserve live builder context reporting");

  obf::mba::clear_mba_counters(&module);
}

void TestCountersFollowFunctionRename() {
  obf::mba::clear_mba_counters();

  llvm::LLVMContext context;
  llvm::Module module("mba.rename", context);
  llvm::Function* function = CreateTestFunction(module, "tracked");
  obf::mba::builder_context builder_context =
      obf::mba::get_or_create_builder_context(*function, "rename", 0x1234ULL);
  builder_context.depth = 1;
  EmitSingleAdd(*function, builder_context);

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*function)),
               1,
               "initial MBA emission must record one shape");

  function->setName("tracked.renamed");

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*function)),
               1,
               "MBA counters must follow renamed functions");

  obf::mba::clear_mba_counters(&module);
}

struct ModuleStorage {
  alignas(llvm::Module) std::byte bytes[sizeof(llvm::Module)];
  llvm::Module* module = nullptr;

  ModuleStorage() = default;
  ModuleStorage(const ModuleStorage&) = delete;
  ModuleStorage& operator=(const ModuleStorage&) = delete;

  ~ModuleStorage() { reset(); }

  llvm::Module& emplace(llvm::LLVMContext& context, llvm::StringRef name) {
    reset();
    module = new (bytes) llvm::Module(name, context);
    return *module;
  }

  void reset() {
    if (module != nullptr) {
      module->~Module();
      module = nullptr;
    }
  }
};

struct StoredModuleLease {
  ModuleStorage& storage;
  llvm::Module& module;

  StoredModuleLease(ModuleStorage& storage, llvm::LLVMContext& context, llvm::StringRef name)
      : storage(storage), module(storage.emplace(context, name)) {}

  StoredModuleLease(const StoredModuleLease&) = delete;
  StoredModuleLease& operator=(const StoredModuleLease&) = delete;

  ~StoredModuleLease() { storage.reset(); }
};

void TestGlobalClearPreservesLiveBuilderContexts() {
  obf::mba::clear_mba_counters();

  llvm::LLVMContext lhs_context;
  llvm::LLVMContext rhs_context;
  llvm::Module lhs_module("mba.global.clear.lhs", lhs_context);
  llvm::Module rhs_module("mba.global.clear.rhs", rhs_context);
  llvm::Function* lhs_function = CreateTestFunction(lhs_module, "lhs");
  llvm::Function* rhs_function = CreateTestFunction(rhs_module, "rhs");

  obf::mba::builder_context lhs_builder_context =
      obf::mba::get_or_create_builder_context(*lhs_function, "global.clear.lhs", 0x4110ULL);
  obf::mba::builder_context rhs_builder_context =
      obf::mba::get_or_create_builder_context(*rhs_function, "global.clear.rhs", 0x4220ULL);
  lhs_builder_context.depth = 1;
  rhs_builder_context.depth = 1;

  auto* lhs_entry = llvm::BasicBlock::Create(lhs_context, "entry", lhs_function);
  auto* lhs_tail = llvm::BasicBlock::Create(lhs_context, "tail", lhs_function);
  llvm::IRBuilder<> lhs_entry_builder(lhs_entry);
  EmitAddChain(lhs_entry_builder,
               lhs_entry_builder.getInt32(1),
               lhs_builder_context,
               0x4310ULL,
               1,
               "obf.mba.global.lhs.entry");
  lhs_entry_builder.CreateBr(lhs_tail);

  auto* rhs_entry = llvm::BasicBlock::Create(rhs_context, "entry", rhs_function);
  auto* rhs_tail = llvm::BasicBlock::Create(rhs_context, "tail", rhs_function);
  llvm::IRBuilder<> rhs_entry_builder(rhs_entry);
  EmitAddChain(rhs_entry_builder,
               rhs_entry_builder.getInt32(2),
               rhs_builder_context,
               0x4410ULL,
               1,
               "obf.mba.global.rhs.entry");
  rhs_entry_builder.CreateBr(rhs_tail);

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*lhs_function)),
               1,
               "global clear setup must record lhs counts");
  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*rhs_function)),
               1,
               "global clear setup must record rhs counts");

  obf::mba::clear_mba_counters();

  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*lhs_function)),
               0,
               "global clear must reset lhs counts");
  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*rhs_function)),
               0,
               "global clear must reset rhs counts");

  llvm::IRBuilder<> lhs_tail_builder(lhs_tail);
  llvm::Value* lhs_result = EmitAddChain(lhs_tail_builder,
                                         lhs_tail_builder.getInt32(3),
                                         lhs_builder_context,
                                         0x4510ULL,
                                         1,
                                         "obf.mba.global.lhs.tail");
  lhs_tail_builder.CreateRet(lhs_result);

  llvm::IRBuilder<> rhs_tail_builder(rhs_tail);
  llvm::Value* rhs_result = EmitAddChain(rhs_tail_builder,
                                         rhs_tail_builder.getInt32(4),
                                         rhs_builder_context,
                                         0x4610ULL,
                                         1,
                                         "obf.mba.global.rhs.tail");
  rhs_tail_builder.CreateRet(rhs_result);

  ExpectTrue(!llvm::verifyFunction(*lhs_function), "global clear lhs function must verify");
  ExpectTrue(!llvm::verifyFunction(*rhs_function), "global clear rhs function must verify");
  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*lhs_function)),
               1,
               "global clear must preserve lhs builder context reporting");
  ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*rhs_function)),
               1,
               "global clear must preserve rhs builder context reporting");

  obf::mba::clear_mba_counters();
}

void TestConcurrentGlobalClearAndEmissionAcrossIndependentContexts() {
  obf::mba::clear_mba_counters();

  constexpr int worker_count = 4;
  constexpr int emission_steps = 48;
  constexpr int clear_iterations = 96;
  std::barrier<> start_barrier(worker_count + 1);
  std::atomic<bool> clear_done = false;
  std::atomic<bool> saw_invalid_ir = false;
  std::atomic<bool> saw_missing_final_counts = false;
  std::vector<std::thread> threads;
  threads.reserve(worker_count + 1);

  for (int worker_index = 0; worker_index < worker_count; ++worker_index) {
    threads.emplace_back([&, worker_index] {
      llvm::LLVMContext context;
      llvm::Module module("mba.concurrent.clear", context);
      llvm::Function* function = CreateTestFunction(module, "tracked");
      obf::mba::builder_context builder_context = obf::mba::get_or_create_builder_context(
          *function, "concurrent.clear", 0x5000ULL + static_cast<std::uint64_t>(worker_index));
      builder_context.depth = 1;

      auto* entry = llvm::BasicBlock::Create(context, "entry", function);
      llvm::IRBuilder<> builder(entry);
      llvm::Value* value = builder.getInt32(worker_index + 1);

      start_barrier.arrive_and_wait();
      value = EmitAddChain(builder,
                           value,
                           builder_context,
                           0x5100ULL + static_cast<std::uint64_t>(worker_index) * 0x100ULL,
                           emission_steps,
                           "obf.mba.concurrent.clear");
      while (!clear_done.load(std::memory_order_acquire)) { std::this_thread::yield(); }

      value = obf::mba::create_add(builder,
                                   value,
                                   builder.getInt32(1),
                                   builder_context,
                                   0x5f00ULL + static_cast<std::uint64_t>(worker_index),
                                   "obf.mba.concurrent.clear.final");
      builder.CreateRet(value);

      if (llvm::verifyFunction(*function)) {
        saw_invalid_ir.store(true, std::memory_order_relaxed);
      }
      if (TotalShapes(obf::mba::get_mba_counters(*function)) == 0) {
        saw_missing_final_counts.store(true, std::memory_order_relaxed);
      }
    });
  }

  threads.emplace_back([&] {
    start_barrier.arrive_and_wait();
    for (int iteration = 0; iteration < clear_iterations; ++iteration) {
      obf::mba::clear_mba_counters();
      if ((iteration & 3) == 0) { std::this_thread::yield(); }
    }
    clear_done.store(true, std::memory_order_release);
  });

  for (std::thread& thread : threads) { thread.join(); }

  ExpectTrue(!saw_invalid_ir.load(std::memory_order_relaxed),
             "concurrent global clear stress must keep IR valid");
  ExpectTrue(!saw_missing_final_counts.load(std::memory_order_relaxed),
             "concurrent global clear stress must keep final counters observable");

  obf::mba::clear_mba_counters();
}

void TestConcurrentFallbackEmissionWithIndependentContextDestruction() {
  obf::mba::clear_mba_counters();

  constexpr int worker_count = 4;
  constexpr int lifetime_rounds = 32;
  constexpr int emission_steps = 8;
  std::barrier<> start_barrier(worker_count + 1);
  std::atomic<bool> saw_invalid_ir = false;
  std::atomic<int> finished_workers = 0;
  std::vector<std::jthread> threads;
  threads.reserve(worker_count + 1);

  for (int worker_index = 0; worker_index < worker_count; ++worker_index) {
    threads.emplace_back([&, worker_index] {
      start_barrier.arrive_and_wait();
      for (int round = 0; round < lifetime_rounds; ++round) {
        llvm::LLVMContext context;
        ModuleStorage storage;
        llvm::Module& module = storage.emplace(context, "mba.concurrent.fallback");
        llvm::Function* function = CreateTestFunction(module, "shared_name");
        const obf::mba::builder_context manual_context{
            .entropy_anchor = obf::mba::get_or_create_entropy_anchor(module),
            .seed_base = 0x6000ULL + static_cast<std::uint64_t>(worker_index) * 0x100ULL +
                         static_cast<std::uint64_t>(round),
            .depth = 1};

        auto* entry = llvm::BasicBlock::Create(context, "entry", function);
        llvm::IRBuilder<> builder(entry);
        llvm::Value* value =
            EmitAddChain(builder,
                         builder.getInt32(worker_index + round + 1),
                         manual_context,
                         0x6100ULL + static_cast<std::uint64_t>(worker_index) * 0x200ULL +
                             static_cast<std::uint64_t>(round) * 0x10ULL,
                         emission_steps,
                         "obf.mba.concurrent.fallback");
        builder.CreateRet(value);

        if (llvm::verifyFunction(*function)) {
          saw_invalid_ir.store(true, std::memory_order_relaxed);
        }
        if ((round & 3) == 0) { std::this_thread::yield(); }
      }
      finished_workers.fetch_add(1, std::memory_order_release);
    });
  }

  threads.emplace_back([&] {
    start_barrier.arrive_and_wait();
    while (finished_workers.load(std::memory_order_acquire) != worker_count) {
      obf::mba::clear_mba_counters();
      std::this_thread::yield();
    }
  });
  for (std::jthread& thread : threads) { thread.join(); }

  ExpectTrue(!saw_invalid_ir.load(std::memory_order_relaxed),
             "fallback emission stress must keep IR valid");

  obf::mba::clear_mba_counters();
}

void TestDestroyedModulesDoNotLeakCountersIntoReusedStorage() {
  obf::mba::clear_mba_counters();

  ModuleStorage storage;

  {
    llvm::LLVMContext first_context;
    StoredModuleLease first_module(storage, first_context, "mba.first");
    llvm::Function* first_function = CreateTestFunction(first_module.module, "shared_name");
    const obf::mba::builder_context manual_context{
        .entropy_anchor = obf::mba::get_or_create_entropy_anchor(first_module.module),
        .seed_base = 0x5678ULL,
        .depth = 1};
    EmitSingleAdd(*first_function, manual_context);

    ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*first_function)),
                 1,
                 "manual MBA context must record one shape before module destruction");
  }

  {
    llvm::LLVMContext second_context;
    StoredModuleLease second_module(storage, second_context, "mba.second");
    llvm::Function* second_function = CreateTestFunction(second_module.module, "shared_name");

    ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*second_function)),
                 0,
                 "destroyed modules must not leak counters into reused module storage");

    const obf::mba::builder_context manual_context{
        .entropy_anchor = obf::mba::get_or_create_entropy_anchor(second_module.module),
        .seed_base = 0x9abcULL,
        .depth = 1};
    EmitSingleAdd(*second_function, manual_context);

    ExpectSizeEq(TotalShapes(obf::mba::get_mba_counters(*second_function)),
                 1,
                 "reused module storage must start from a fresh MBA counter sink");
  }

  obf::mba::clear_mba_counters();
}

}  // namespace

int main() {
  TestModuleClearPreservesLiveBuilderContexts();
  TestGlobalClearPreservesLiveBuilderContexts();
  TestCountersFollowFunctionRename();
  TestDestroyedModulesDoNotLeakCountersIntoReusedStorage();
  TestConcurrentGlobalClearAndEmissionAcrossIndependentContexts();
  TestConcurrentFallbackEmissionWithIndependentContextDestruction();

  if (g_failures == 0) {
    std::cout << "[ok] mba_lifetime_tests passed" << '\n';
    return 0;
  }

  std::cerr << "[fail] mba_lifetime_tests failures=" << g_failures << '\n';
  return 1;
}
