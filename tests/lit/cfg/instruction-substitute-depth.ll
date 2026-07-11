; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute-depth.yaml --obf-seed=1 -passes=obf-instruction-substitute -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

define i32 @value(i32 %x, i32 %y) {
entry:
  %lhs = and i32 %x, %y
  %rhs = or i32 %lhs, 3
  ret i32 %rhs
}

define i32 @main() {
entry:
  %value = call i32 @value(i32 10, i32 20)
  %ok = icmp eq i32 %value, 3
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; @value is level strong, so and/or are substituted, and under strong classical
; up to two sites gain a depth-3 MBA opaque-zero pad. The identity family per op
; is seed/path dependent; assert only that each op's chain and the MBA pad exist.
; CHECK-LABEL: define i32 @value
; CHECK-DAG: %obf.and.
; CHECK-DAG: %obf.or.
; CHECK-DAG: %obf.subst.pad
