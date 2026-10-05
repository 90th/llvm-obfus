#pragma once

#include "llvm/ADT/ArrayRef.h"

#include <memory>

namespace llvm {
class Module;
}

namespace obf {
struct function_pipeline_state;
struct string_encoding_result;

// A native-only snapshot of source ownership. Value handles follow final names
// without keeping source globals or functions alive through lowering.
class native_string_ownership {
 public:
  native_string_ownership(llvm::Module& module,
                          llvm::ArrayRef<function_pipeline_state> states,
                          bool native_route);
  ~native_string_ownership();

  native_string_ownership(const native_string_ownership&) = delete;
  native_string_ownership& operator=(const native_string_ownership&) = delete;

  void record_string_encoding(llvm::ArrayRef<string_encoding_result> results);
  bool emit(llvm::Module& module);

 private:
  struct snapshot;
  std::unique_ptr<snapshot> snapshot_;
};
}  // namespace obf
