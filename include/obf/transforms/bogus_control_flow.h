#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct bogus_control_flow_options {
  std::size_t max_insertions_per_function = 1;
  std::uint32_t mba_depth = 1;
};

struct bogus_control_flow_result {
  std::size_t insertion_count = 0;
  std::string detail;
};

bogus_control_flow_result
analyze_bogus_control_flow(const llvm::Function &function,
                           const bogus_control_flow_options &options);

bogus_control_flow_result
run_bogus_control_flow(llvm::Function &function,
                       const bogus_control_flow_options &options);

} // namespace obf
