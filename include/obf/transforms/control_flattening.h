#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct control_flattening_options {
  std::size_t min_blocks = 3;
  std::size_t max_blocks = 12;
  std::size_t max_instructions = 128;
  std::size_t max_decoy_states = 2;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
  std::uint64_t seed = 0;
};

struct control_flattening_result {
  bool flattened = false;
  std::size_t state_count = 0;
  std::size_t conditional_branches = 0;
  std::string detail;
};

control_flattening_result analyze_control_flattening(const llvm::Function& function,
                                                     const control_flattening_options& options);

control_flattening_result run_control_flattening(llvm::Function& function,
                                                 const control_flattening_options& options);

}  // namespace obf
