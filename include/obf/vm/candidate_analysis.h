#pragma once

#include "obf/vm/micro_ir.h"

#include <cstddef>
#include <string>

namespace llvm {
class Function;
}

namespace obf::vm {

struct candidate_result {
  bool eligible = false;
  std::size_t instruction_count = 0;
  std::string detail;
};

candidate_result analyze_candidate(const llvm::Function& function,
                                   bytecode_program* program = nullptr);

}  // namespace obf::vm
