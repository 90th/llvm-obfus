#pragma once

#include <cstddef>
#include <string>

namespace llvm {
class Function;
}

namespace obf {

struct opaque_predicate_options {
  std::size_t max_insertions_per_function = 2;
};

struct opaque_predicate_result {
  std::size_t insertion_count = 0;
  std::string detail;
};

opaque_predicate_result
analyze_opaque_predicates(const llvm::Function &function,
                          const opaque_predicate_options &options);

opaque_predicate_result
run_opaque_predicates(llvm::Function &function,
                      const opaque_predicate_options &options);

} // namespace obf
