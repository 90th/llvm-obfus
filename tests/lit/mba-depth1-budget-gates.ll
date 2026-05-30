; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-depth1-budget-gates.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-depth1-budget-gates.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-depth1-budget-gates.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @depth1_shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  ret i32 %d
}

define i32 @main() {
entry:
  %value = call i32 @depth1_shape_mix(i32 7)
  %ok = icmp eq i32 %value, 8842
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @depth1_shape_mix(i32 %x)
; CHECK-NOT: obf.mba.zero.linear_equiv_pair
; CHECK-NOT: obf.mba.add.xor_shifted_carry
; CHECK-NOT: obf.mba.sub.ones_complement
; CHECK-NOT: obf.mba.xor.sum_minus_carry
; CHECK-NOT: obf.seed.xor_split
; CHECK-NOT: obf.seed.add_split
; CHECK-NOT: obf.seed.affine
; CHECK-NOT: obf.seed.zero_add
; CHECK-NOT: obf.mba.zero.poly_binomial
; CHECK-NOT: obf.mba.zero.poly_affine
; CHECK: ret i32
