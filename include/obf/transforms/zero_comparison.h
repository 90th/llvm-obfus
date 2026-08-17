#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct zero_comparison_options {
  std::size_t max_sites_per_function = 4;
  std::size_t max_unroll_bytes = 64;
  bool transform_string_comparisons = true;
  bool transform_integer_comparisons = true;
  std::uint64_t seed = 0;
};

struct zero_comparison_result {
  std::size_t transformed_site_count = 0;
  std::string detail;
};

zero_comparison_result analyze_zero_comparison(const llvm::Function& function,
                                               const zero_comparison_options& options);

zero_comparison_result run_zero_comparison(llvm::Function& function,
                                           const zero_comparison_options& options);

}  // namespace obf
