#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace llvm {
class Function;
}

namespace obf::vm {

struct virtualization_options {
  std::uint32_t mba_depth = 1;
  bool hidden_token_handshake = false;
  std::vector<std::uint64_t> valid_hidden_tokens;
  std::string symbol_tag;
};

struct virtualization_result {
  bool virtualized = false;
  std::size_t instruction_count = 0;
  std::string detail;
};

virtualization_result run_virtualization(llvm::Function &function,
                                        const virtualization_options &options = {});

} // namespace obf::vm
