; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-integer-safety.yaml -passes=obf-vm -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for non-FP FastMathFlags safety and integer lowering in VM handlers:
; Instructions like sdiv, udiv, srem, urem, shl, ashr, lshr and non-FP calls
; must NOT have setFastMathFlags called on them, ensuring LLVM verifier/assertion compliance.

declare i32 @helper_callee(i32)

define i32 @helper_callee_impl(i32 %x) {
entry:
  %res = add i32 %x, 10
  ret i32 %res
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_
define i32 @vm_int_ops(i32 %a, i32 %b) {
entry:
  %d1 = sdiv i32 %a, 2
  %d2 = udiv i32 %b, 3
  %r1 = srem i32 %a, 5
  %r2 = urem i32 %b, 7
  %s1 = shl i32 %a, 1
  %s2 = ashr i32 %a, 2
  %s3 = lshr i32 %b, 1
  %c = call i32 @helper_callee_impl(i32 %a)
  %t1 = add i32 %d1, %d2
  %t2 = add i32 %t1, %r1
  %t3 = add i32 %t2, %r2
  %t4 = add i32 %t3, %s1
  %t5 = add i32 %t4, %s2
  %t6 = add i32 %t5, %s3
  %res = add i32 %t6, %c
  ret i32 %res
}

define i32 @main() {
entry:
  ; a = 20, b = 21
  ; d1 = 20 / 2 = 10
  ; d2 = 21 / 3 = 7
  ; r1 = 20 % 5 = 0
  ; r2 = 21 % 7 = 0
  ; s1 = 20 << 1 = 40
  ; s2 = 20 >> 2 = 5
  ; s3 = 21 >> 1 = 10
  ; c = 20 + 10 = 30
  ; sum = 10 + 7 + 0 + 0 + 40 + 5 + 10 + 30 = 102
  %val = call i32 @vm_int_ops(i32 20, i32 21)
  %ok = icmp eq i32 %val, 102
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
