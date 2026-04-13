; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/instruction-substitute.yaml -passes=obf-instruction-substitute -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/instruction-substitute.yaml -passes=obf-instruction-substitute -S %s -o %t
; RUN: %lli %t

define i32 @value(i32 %x, i32 %y) {
entry:
  %sum = add i32 %x, %y
  %mix = xor i32 %sum, 123
  ret i32 %mix
}

define i32 @main() {
entry:
  %value = call i32 @value(i32 10, i32 20)
  %ok = icmp eq i32 %value, 101
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK-LABEL: define i32 @value
; CHECK: %obf.mba.add.xor = xor i32 %x, %y
; CHECK: %obf.mba.add.and = and i32 %x, %y
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: store i64 %obf.entropy.direct, ptr %obf.entropy.ref
; CHECK: %obf.mba.add.carry = add i32 %obf.mba.add.and, %obf.mba.add.carry.mask
; CHECK: %sum = add i32 %obf.mba.add.xor.mask, %obf.mba.add.carry
; CHECK: %mix = sub i32 %obf.mba.xor.left, %obf.mba.xor.right
