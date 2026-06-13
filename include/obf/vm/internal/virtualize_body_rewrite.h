#ifndef OBF_VM_INTERNAL_VIRTUALIZE_BODY_REWRITE_H
#define OBF_VM_INTERNAL_VIRTUALIZE_BODY_REWRITE_H

#include "llvm/IR/Function.h"

namespace obf::vm {

struct bytecode_program;
struct virtualization_options;

void rewrite_function_body(llvm::Function& function,
                           const bytecode_program& program,
                           const virtualization_options& options);

}  // namespace obf::vm

#endif
