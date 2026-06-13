#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_TARGET_DISCOVERY_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_TARGET_DISCOVERY_H

#include "obf/plugin/internal/plugin_vm_types.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"

#include <cstdint>

namespace obf {

struct function_pipeline_state;

llvm::SmallVector<vm_target_candidate, 8>
discover_vm_targets_for_state(const function_pipeline_state& state,
                              llvm::StringSet<>& skip_functions,
                              std::uint64_t& helper_ordinal,
                              bool preserve_generated_names);

}  // namespace obf

#endif
