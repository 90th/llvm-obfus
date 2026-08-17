#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace llvm {
class Function;
class Module;
}  // namespace llvm

namespace obf {

struct self_checksum_options {
  bool enabled = false;
  std::uint32_t sample_window_bytes = 16;
  std::uint32_t max_checksum_sites = 2;
  std::uint64_t seed = 0;
};

struct self_checksum_result {
  std::size_t checksum_site_count = 0;
  std::size_t keyed_value_count = 0;
  std::size_t skipped_no_target = 0;
  std::string detail;
};

self_checksum_result transform_self_checksum(llvm::Function& function,
                                             llvm::Module& module,
                                             const self_checksum_options& options);

}  // namespace obf
