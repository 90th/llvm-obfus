; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-budget-exhausted.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-budget-exhausted.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-budget-exhausted.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
; seed determinism: tight budget must choose the same fallback path each time
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-budget-exhausted.yaml -passes=obf-constant-encode -S %s -o %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-budget-exhausted.yaml -passes=obf-constant-encode -S %s -o %t.second
; RUN: cmp %t.first %t.second

; With max_ir_instructions=8 at depth 3, each create_add call starts
; a new BudgetTracker with 8 points.  Two levels of expansion consume
; 4+4=8 points, so the third level falls back to a plain LLVM add.
; The function must still produce the correct result.

define i32 @budget_tight(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  %e = add i32 %d, 1
  %f = sub i32 %e, 2
  %g = xor i32 %f, 3
  ret i32 %g
}

define i32 @main() {
entry:
  %value = call i32 @budget_tight(i32 7)
  %ok = icmp eq i32 %value, 8842
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; With a tight budget every public create_add/sub/xor call starts its
; own tracker.  Depth-3 expansion drains the tracker after two levels.
; Verify the entropy anchor and opaque zero infrastructure are still
; wired in, and that the function still computes the correct result.
;
; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @budget_tight(i32 %x)
; CHECK: ret i32
