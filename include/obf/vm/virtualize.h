#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf::vm {

struct virtualization_options {
  std::uint32_t mba_depth = 1;
};

struct virtualization_result {
  bool virtualized = false;
  std::size_t instruction_count = 0;
  std::string detail;
};

virtualization_result run_virtualization(llvm::Function &function,
                                        const virtualization_options &options = {});

} // namespace obf::vm
