#include "obf/vm/internal/virtualize_body_rewrite.h"
#include "obf/vm/virtualize_internal.h"

#include "obf/vm/candidate_analysis.h"

#include "llvm/IR/Function.h"

namespace obf::vm {

virtualization_result run_virtualization(llvm::Function& function,
                                         const virtualization_options& options) {
  bytecode_program program;
  const candidate_result analysis = analyze_candidate(function, &program);
  if (!analysis.eligible) { return {.virtualized = false, .detail = analysis.detail}; }

  rewrite_function_body(function, program, options);
  return {.virtualized = true,
          .instruction_count = analysis.instruction_count,
          .detail =
              std::to_string(analysis.instruction_count) + " virtual instruction(s) emitted"};
}

}  // namespace obf::vm
