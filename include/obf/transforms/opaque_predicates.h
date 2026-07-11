#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
class Module;
}  // namespace llvm

namespace obf {

struct opaque_predicate_options {
  std::size_t max_insertions_per_function = 2;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
  std::uint64_t seed = 0;
};

struct opaque_predicate_result {
  std::size_t insertion_count = 0;
  std::string detail;
};

opaque_predicate_result analyze_opaque_predicates(const llvm::Function& function,
                                                  const opaque_predicate_options& options);

opaque_predicate_result run_opaque_predicates(llvm::Function& function,
                                              const opaque_predicate_options& options);

bool RunCfgStateCleanup(llvm::Module& module);

}  // namespace obf
