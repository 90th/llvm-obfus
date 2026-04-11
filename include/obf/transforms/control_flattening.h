#pragma once

#include <cstddef>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct control_flattening_options {
  std::size_t min_blocks = 3;
  std::size_t max_blocks = 12;
  std::size_t max_instructions = 128;
};

struct control_flattening_result {
  bool flattened = false;
  std::size_t state_count = 0;
  std::size_t conditional_branches = 0;
  std::string detail;
};

control_flattening_result
analyze_control_flattening(const llvm::Function &function,
                           const control_flattening_options &options);

control_flattening_result
run_control_flattening(llvm::Function &function,
                       const control_flattening_options &options);

} // namespace obf
