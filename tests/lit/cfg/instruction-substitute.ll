; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml -passes=obf-instruction-substitute -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml -passes=obf-instruction-substitute -S %s -o %t
; RUN: %lli %t

define i32 @value(i32 %x, i32 %y) {
entry:
  %lhs = and i32 %x, %y
  %rhs = or i32 %lhs, 123
  ret i32 %rhs
}

define i32 @main() {
entry:
  %value = call i32 @value(i32 10, i32 20)
  %ok = icmp eq i32 %value, 123
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @value
; CHECK: %obf.and.notlhs = xor i32 %x, -1
; CHECK: %obf.and.notrhs = xor i32 %y, -1
; CHECK: %lhs = xor i32 %obf.and.or, -1
; CHECK: %obf.or.notlhs = xor i32 %lhs, -1
; CHECK: %obf.or.and = and i32 %obf.or.notlhs, -124
; CHECK: %rhs = xor i32 %obf.or.and, -1
