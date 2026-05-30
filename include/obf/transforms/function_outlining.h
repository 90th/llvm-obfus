#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct function_outlining_options {
  std::size_t min_cluster_size = 2;
  std::size_t max_cluster_size = 4;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
  std::uint64_t seed = 0;
};

struct function_outlining_result {
  std::size_t shard_count = 0;
  std::string detail;
};

function_outlining_result analyze_function_outlining(const llvm::Function& function,
                                                     const function_outlining_options& options);

function_outlining_result run_function_outlining(llvm::Function& function,
                                                 const function_outlining_options& options);

}  // namespace obf
