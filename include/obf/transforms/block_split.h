#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct block_split_options {
  std::size_t max_splits_per_function = 1;
  std::size_t min_instructions_per_block = 2;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
};

struct block_split_result {
  std::size_t split_count = 0;
  std::string detail;
};

block_split_result analyze_block_split(const llvm::Function& function,
                                       const block_split_options& options,
                                       std::uint64_t seed);

block_split_result
run_block_split(llvm::Function& function, const block_split_options& options, std::uint64_t seed);

}  // namespace obf
