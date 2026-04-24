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
; CHECK-LABEL: define i32 @value
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: %obf.entropy.cache.init = call { i64, i64 } @__obf_entropy_thunk_
; CHECK: %obf.mba.add.xor = xor i32 %x, %y
; CHECK: %obf.mba.add.and = and i32 %x, %y
; CHECK: %obf.entropy.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.entropy.direct = extractvalue { i64, i64 } %obf.entropy.pair, 0
; CHECK: %obf.entropy.indirect = extractvalue { i64, i64 } %obf.entropy.pair, 1
; CHECK: %obf.mba.add.carry = add i32 %obf.mba.add.and, %obf.mba.add.carry.mask
; CHECK: %sum = add i32 %obf.mba.add.xor.mask, %obf.mba.add.carry
; CHECK: %mix = sub i32 %obf.mba.xor.left, %obf.mba.xor.right
