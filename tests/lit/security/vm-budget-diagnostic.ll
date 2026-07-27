; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-budget.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s

define i32 @budget_target(i32 %x) {
entry:
  %a = add i32 %x, 7
  %b = mul i32 %a, 3
  ret i32 %b
}

; CHECK: LLVM ERROR: strong_vm invariant violation
; CHECK-SAME: too many virtual instructions
; CHECK-SAME: reason_tag=virtual_instruction_budget_exceeded
