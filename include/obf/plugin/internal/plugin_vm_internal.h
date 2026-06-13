#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_INTERNAL_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_INTERNAL_H

#include "obf/plugin/internal/plugin_vm_types.h"

namespace obf {

enum class vm_resolver_shape {
  cached_sentinel_global,
  local_always_decode,
};

enum class vm_seed_resolver_shape {
  shared_switch_resolver,
  local_inline_resolver,
};

enum class vm_pointer_materialization_shape {
  direct_ptrtoint,
  split_xor_chunks,
  add_sub_bias,
};

enum class vm_entry_thunk_shape {
  direct_forward,
  neutral_forward,
  split_forward,
  indirect_ptr_forward,
  decoy_guarded_forward,
};

}  // namespace obf

#endif
