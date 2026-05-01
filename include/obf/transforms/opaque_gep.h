#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct opaque_gep_options {
  std::uint32_t mba_depth = 1;
};

struct opaque_gep_result {
  std::size_t lowered_count = 0;
  std::string detail;
};

opaque_gep_result analyze_opaque_gep(const llvm::Function& function,
                                     const opaque_gep_options& options);

opaque_gep_result run_opaque_gep(llvm::Function& function, const opaque_gep_options& options);

}  // namespace obf
