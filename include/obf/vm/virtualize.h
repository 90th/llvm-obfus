#pragma once

#include <cstddef>
#include <string>

namespace llvm {
class Function;
}

namespace obf::vm {

struct virtualization_result {
  bool virtualized = false;
  std::size_t instruction_count = 0;
  std::string detail;
};

virtualization_result run_virtualization(llvm::Function &function);

} // namespace obf::vm
