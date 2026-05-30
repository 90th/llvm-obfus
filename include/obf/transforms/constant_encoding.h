#pragma once

#include "obf/frontend/config.h"

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/StringRef.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace llvm {
class Function;
class Module;
}

namespace obf {

using protected_constant_function_seed_lookup =
    llvm::function_ref<std::optional<std::uint64_t>(llvm::StringRef)>;

struct constant_encoding_options {
  constant_protection_mode mode = constant_protection_mode::mba_inline;
  std::size_t max_constants_per_function = 4;
  unsigned min_bit_width = 8;
  std::uint32_t mba_depth = 1;
  std::optional<std::uint32_t> mba_max_ir_instructions;
  std::optional<bool> mba_enable_polynomial;
  std::optional<bool> mba_enable_multiplication;
};

struct constant_encoding_result {
  std::size_t encoded_count = 0;
  std::string detail;
};

constant_encoding_result analyze_constant_encoding(const llvm::Function& function,
                                                   const constant_encoding_options& options,
                                                   std::uint64_t seed);

constant_encoding_result run_constant_encoding(llvm::Function& function,
                                               const constant_encoding_options& options,
                                               std::uint64_t seed);

constant_encoding_result run_constant_encoding(llvm::Module& module,
                                               protected_constant_function_seed_lookup get_seed,
                                               const constant_encoding_options& options,
                                               std::uint64_t seed);

}  // namespace obf
