#ifndef OBF_PLUGIN_INTERNAL_PLUGIN_VM_CALLSITE_REWRITING_H
#define OBF_PLUGIN_INTERNAL_PLUGIN_VM_CALLSITE_REWRITING_H

#include "obf/plugin/internal/plugin_vm_types.h"

#include <cstdint>

namespace obf {

class live_proxy_site_registry;

bool rewrite_calls_to_virtualized_functions(llvm::Module& module,
                                            const virtualized_function_map& virtualized_functions,
                                            std::uint32_t mba_depth,
                                            live_proxy_site_registry* registry);
}

#endif
