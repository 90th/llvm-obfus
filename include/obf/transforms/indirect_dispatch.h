#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct indirect_dispatch_options {
  bool enabled = false;
  std::size_t max_sites_per_function = 4;
  std::size_t max_switch_targets = 8;
  bool target_vm_dispatchers = true;
  bool target_flattened_headers = true;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
  std::uint64_t seed = 0;
};

struct indirect_dispatch_result {
  std::size_t site_count = 0;
  std::size_t branch_site_count = 0;
  std::size_t switch_site_count = 0;
  std::size_t skipped_max_switch_targets = 0;
  std::size_t first_oversized_switch_targets = 0;
  std::size_t max_switch_targets_limit = 0;
  std::size_t blocked_non_integral_program_address_space = 0;
  std::size_t blocked_unsupported_function_shape = 0;
  std::string detail;
};

indirect_dispatch_result analyze_indirect_dispatch(const llvm::Function& function,
                                                   const indirect_dispatch_options& options);

indirect_dispatch_result run_indirect_dispatch(llvm::Function& function,
                                               const indirect_dispatch_options& options);

}  // namespace obf
