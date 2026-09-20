; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-integer-safety.yaml -passes=obf-vm -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for constant-folded VM lowering.
; `materialize_integer_constant()` only leaves 0/1/-1 as raw integer constants,
; while `materialize_constant()` passes floating-point constants through unchanged.
; Use those values so handler lowering really sees foldable operands.

; - `or i32 0, -1` reaches emit_current_integer_binary -> emit_plain_integer_binary.
; - `shl i32 1, 0` and `sdiv i32 1, 1` reach emit_binary's post-switch flag path.
; - `fcmp fast`/`fneg fast` with FP constants reach the folded non-Instruction
;   path while still carrying encoded FMF bits through analysis.

; CHECK-LABEL: define internal i32 @__obf_vm_i_
define i32 @vm_int_folded_scalar_path() {
entry:
  %fold.or = or i32 0, -1
  ret i32 %fold.or
}

define i32 @vm_int_folded_switch_path() {
entry:
  %fold.shl = shl i32 1, 0
  %fold.div = sdiv i32 1, 1
  %res = add i32 %fold.shl, %fold.div
  ret i32 %res
}

define i32 @vm_int_folded_fcmp_path() {
entry:
  %cmp = fcmp fast oeq float 1.000000e+00, 1.000000e+00
  %ret = select i1 %cmp, i32 7, i32 9
  ret i32 %ret
}

define i32 @vm_int_folded_fneg_path() {
entry:
  %neg = fneg fast float 2.000000e+00
  %bits = bitcast float %neg to i32
  ret i32 %bits
}

define i32 @main() {
entry:
  %lhs = call i32 @vm_int_folded_scalar_path()
  %rhs = call i32 @vm_int_folded_switch_path()
  %cmp = call i32 @vm_int_folded_fcmp_path()
  %neg = call i32 @vm_int_folded_fneg_path()
  %ints = add i32 %lhs, %rhs
  %sum = add i32 %ints, %cmp
  %sum.ok = icmp eq i32 %sum, 8
  %neg.ok = icmp eq i32 %neg, -1073741824
  %ok = and i1 %sum.ok, %neg.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
