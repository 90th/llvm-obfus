#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct instruction_substitution_options {
  std::size_t max_substitutions_per_function = 4;
  std::size_t max_padded_sites = 0;      // transform-level MBA-padding quota
  std::uint64_t seed = 0;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
};

struct instruction_substitution_result {
  std::size_t substitution_count = 0;
  std::string detail;
};

instruction_substitution_result
analyze_instruction_substitution(const llvm::Function& function,
                                 const instruction_substitution_options& options);

instruction_substitution_result
run_instruction_substitution(llvm::Function& function,
                             const instruction_substitution_options& options);

}  // namespace obf
