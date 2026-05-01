#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct constant_encoding_options {
  std::size_t max_constants_per_function = 4;
  unsigned min_bit_width = 8;
  std::uint32_t mba_depth = 1;
};

struct constant_encoding_result {
  std::size_t encoded_count = 0;
  std::string detail;
};

constant_encoding_result analyze_constant_encoding(const llvm::Function& function,
                                                   const constant_encoding_options& options,
                                                   std::uint64_t seed);

constant_encoding_result run_constant_encoding(llvm::Function& function,
                                               const constant_encoding_options& options,
                                               std::uint64_t seed);

}  // namespace obf
