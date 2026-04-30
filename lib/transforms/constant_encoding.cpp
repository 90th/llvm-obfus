#include "obf/transforms/constant_encoding.h"

#include "obf/support/stable_hash.h"
#include "obf/transforms/mba.h"

#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include <cstdint>
#include <string>

namespace obf {

namespace {

bool is_trivial_constant(const llvm::ConstantInt &constant) {
  return constant.isZero() || constant.isOne() || constant.isMinusOne();
}

bool is_supported_instruction(const llvm::Instruction &instruction) {
  return llvm::isa<llvm::BinaryOperator>(instruction) ||
         llvm::isa<llvm::ICmpInst>(instruction) ||
         llvm::isa<llvm::SelectInst>(instruction) ||
         llvm::isa<llvm::ReturnInst>(instruction) ||
         llvm::isa<llvm::StoreInst>(instruction) ||
         llvm::isa<llvm::CallBase>(instruction);
}

bool is_supported_constant_operand(const llvm::Instruction &instruction,
                                   unsigned operand_index,
                                   const llvm::ConstantInt &constant,
                                   const constant_encoding_options &options) {
  if (!is_supported_instruction(instruction) || is_trivial_constant(constant) ||
      constant.getBitWidth() < options.min_bit_width) {
    return false;
  }

  if (const auto *call = llvm::dyn_cast<llvm::CallBase>(&instruction)) {
    if (operand_index >= call->arg_size()) {
      return false;
    }

    if (call->paramHasAttr(operand_index, llvm::Attribute::ImmArg)) {
      return false;
    }

    if (const llvm::Function *callee = call->getCalledFunction()) {
      if (callee->isIntrinsic()) {
        return false;
      }
    }

    return true;
  }

  return true;
}

std::uint64_t mix_seed(std::uint64_t seed, std::uint64_t salt) {
  seed ^= salt + 0x9e3779b97f4a7c15ULL + (seed << 6) + (seed >> 2);
  return seed;
}

llvm::APInt derive_key(unsigned bit_width, std::uint64_t seed) {
  llvm::APInt key(bit_width, seed, false, true);
  if (key.isZero()) {
    key = llvm::APInt(bit_width, 0x5aU);
  }

  return key;
}

std::uint64_t derive_opaque_seed(const llvm::Function &function,
                                 std::uint64_t seed) {
  seed = mix_seed(seed, stable_hash_string(function.getName()));
  if (seed == 0) {
    seed = 0x5aa55aa55aa55aa5ULL;
  }

  return seed;
}

llvm::Value *build_opaque_mask(llvm::IRBuilder<> &builder,
                               std::uint64_t opaque_seed_base,
                               llvm::IntegerType *type, const llvm::APInt &key,
                               const mba::builder_context &mba_context,
                               std::uint64_t salt) {
  const llvm::APInt base_seed(type->getBitWidth(), opaque_seed_base,
                              /*isSigned=*/false, /*implicitTrunc=*/true);
  mba::builder_context seed_context = mba_context;
  seed_context.seed_base = opaque_seed_base;
  llvm::Value *typed_seed = mba::create_opaque_integer(
      builder, type, seed_context, base_seed, salt ^ 0x55aa55aaULL,
      "obf.const.seed");
  const llvm::APInt delta = key ^ base_seed;
  return mba::create_xor(builder, typed_seed,
                         llvm::ConstantInt::get(type, delta), mba_context,
                         salt, "obf.const.mask");
}

constant_encoding_result analyze_impl(const llvm::Function &function,
                                      const constant_encoding_options &options) {
  if (function.isDeclaration()) {
    return {.encoded_count = 0, .detail = "declaration"};
  }

  if (options.max_constants_per_function == 0) {
    return {.encoded_count = 0,
            .detail = "max_constants_per_function is zero"};
  }

  std::size_t encoded_count = 0;
  for (const llvm::BasicBlock &block : function) {
    for (const llvm::Instruction &instruction : block) {
      for (unsigned operand_index = 0; operand_index < instruction.getNumOperands();
           ++operand_index) {
        const auto *constant =
            llvm::dyn_cast<llvm::ConstantInt>(instruction.getOperand(operand_index));
        if (constant == nullptr ||
            !is_supported_constant_operand(instruction, operand_index, *constant,
                                           options)) {
          continue;
        }

        ++encoded_count;
        if (encoded_count >= options.max_constants_per_function) {
          return {.encoded_count = encoded_count,
                  .detail = std::to_string(encoded_count) +
                            " constant(s) available"};
        }
      }
    }
  }

  if (encoded_count == 0) {
    return {.encoded_count = 0, .detail = "no eligible integer constants"};
  }

  return {.encoded_count = encoded_count,
          .detail = std::to_string(encoded_count) +
                    " constant(s) available"};
}

} // namespace

constant_encoding_result analyze_constant_encoding(
    const llvm::Function &function, const constant_encoding_options &options,
    std::uint64_t) {
  return analyze_impl(function, options);
}

constant_encoding_result run_constant_encoding(llvm::Function &function,
                                               const constant_encoding_options &options,
                                               std::uint64_t seed) {
  const constant_encoding_result analysis = analyze_impl(function, options);
  if (analysis.encoded_count == 0) {
    return analysis;
  }

  std::size_t encoded_count = 0;
  std::uint64_t local_seed = seed;
  const std::uint64_t opaque_seed_base = derive_opaque_seed(function, seed);

  llvm::SmallVector<llvm::Instruction *, 64> original_instructions;
  for (llvm::BasicBlock &block : function) {
    for (llvm::Instruction &instruction : block) {
      original_instructions.push_back(&instruction);
    }
  }

  const mba::builder_context mba_context =
      [&] {
        mba::builder_context ctx =
            mba::get_or_create_builder_context(function, "obf.const.mba",
                                               opaque_seed_base);
        ctx.depth = options.mba_depth;
        return ctx;
      }();

  for (llvm::Instruction *instruction : original_instructions) {
    if (instruction == nullptr || encoded_count >= options.max_constants_per_function) {
      continue;
    }

    for (unsigned operand_index = 0; operand_index < instruction->getNumOperands();
         ++operand_index) {
      if (encoded_count >= options.max_constants_per_function) {
        break;
      }

      auto *constant =
          llvm::dyn_cast<llvm::ConstantInt>(instruction->getOperand(operand_index));
      if (constant == nullptr ||
          !is_supported_constant_operand(*instruction, operand_index, *constant,
                                         options)) {
        continue;
      }

      local_seed = mix_seed(local_seed,
                            static_cast<std::uint64_t>(encoded_count + 1));
      const llvm::APInt key = derive_key(constant->getBitWidth(), local_seed);
      const llvm::APInt encoded = constant->getValue() ^ key;

      llvm::IRBuilder<> builder(instruction);
      llvm::Value *mask = build_opaque_mask(
          builder, opaque_seed_base,
          llvm::cast<llvm::IntegerType>(constant->getType()), key, mba_context,
          local_seed ^ static_cast<std::uint64_t>(operand_index + 1));
      llvm::Value *decoded = mba::create_xor(
          builder, llvm::ConstantInt::get(constant->getType(), encoded), mask,
          mba_context, local_seed ^ 0xd6e8feb86659fd93ULL, "obf.const");
      instruction->setOperand(operand_index, decoded);
      ++encoded_count;
    }
  }

  return {.encoded_count = encoded_count,
          .detail = std::to_string(encoded_count) + " constant(s) encoded"};
}

} // namespace obf
