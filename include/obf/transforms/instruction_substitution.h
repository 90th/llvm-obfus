#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct instruction_substitution_options {
  std::size_t max_substitutions_per_function = 4;
  std::uint32_t mba_depth = 1;
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
