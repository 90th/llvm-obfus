#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct lifter_destruction_options {
  bool enabled = false;
  std::size_t max_sites_per_function = 1;
  std::uint32_t mba_depth = 1;
};

struct lifter_destruction_result {
  std::size_t insertion_count = 0;
  std::string detail;
};

lifter_destruction_result analyze_lifter_destruction(const llvm::Function& function,
                                                     const lifter_destruction_options& options);

lifter_destruction_result run_lifter_destruction(llvm::Function& function,
                                                 const lifter_destruction_options& options,
                                                 std::uint64_t seed);

}  // namespace obf
