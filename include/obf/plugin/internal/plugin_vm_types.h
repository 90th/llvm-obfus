#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_TYPES_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_TYPES_H

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/ValueHandle.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace obf {

struct function_pipeline_state;

struct virtualized_call_site {
  llvm::WeakTrackingVH call;
  std::uint64_t hidden_token = 0;
};

struct virtualized_function_binding {
  llvm::Function* interface_function = nullptr;
  llvm::Function* implementation_function = nullptr;
  const function_pipeline_state* state = nullptr;
  llvm::SmallVector<virtualized_call_site, 8> call_sites;
  std::uint64_t wrapper_token = 0;
  std::string vm_symbol_tag;
  std::string target_cache_global_name;
  std::string target_seed_global_name;
  std::string decode_key_global_name;
  std::string seed_case_function_name;
  bool uses_target_cache = false;
  bool uses_shared_seed_resolver = false;
  llvm::Function* entry_thunk_function = nullptr;
  std::string entry_thunk_function_name;
};

using virtualized_function_map = llvm::StringMap<virtualized_function_binding>;

struct vm_target_candidate {
  llvm::Function* function = nullptr;
  const function_pipeline_state* state = nullptr;
  std::size_t nesting_depth = 0;
};

}  // namespace obf

#endif
