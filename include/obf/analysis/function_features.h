#pragma once

#include <cstddef>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct function_features {
  std::string name;
  std::size_t instruction_count = 0;
  std::size_t basic_block_count = 0;
  std::size_t cyclomatic_complexity = 0;
  std::size_t call_count = 0;
  std::size_t string_ref_count = 0;
  bool has_loops = false;
  bool has_exception_edges = false;
  bool has_inline_asm = false;
  bool has_vector_ops = false;
  bool is_recursive = false;
  bool address_taken = false;
  bool is_declaration = false;
};

function_features collect_function_features(const llvm::Function &function);

} // namespace obf
