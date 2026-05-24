; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-auto.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=AUTO
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-auto.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

@lut = private constant [3 x i32] [i32 7, i32 11, i32 13], align 4

define i32 @auto_mix(i32 %x) {
entry:
  %a = add i32 %x, 9
  %b = xor i32 %a, 31337
  %c = add i32 %b, 31337
  ret i32 %c
}

define i32 @use_table(i32 %idx) {
entry:
  %wide = sext i32 %idx to i64
  %slot = getelementptr inbounds [3 x i32], ptr @lut, i64 0, i64 %wide
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}

define i32 @main() {
entry:
  %lhs = call i32 @auto_mix(i32 5)
  %rhs = call i32 @use_table(i32 1)
  %sum = add i32 %lhs, %rhs
  %ok = icmp eq i32 %sum, 62683
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; AUTO: @__obf_const_pool_
; AUTO-LABEL: define i32 @auto_mix(i32 %x) {
; AUTO: %obf.const.mask = {{(add|sub) i32}}
; AUTO: %a = add i32 %x, %obf.const
; AUTO: %obf.const.pool.base = call ptr @__obf_const_pool_decode_
; AUTO: %b = xor i32 %a, %obf.const.pool.load
; AUTO: %c = add i32 %b, %obf.const.pool.load{{[0-9]+}}
; AUTO-LABEL: define i32 @use_table(i32 %idx) {
; AUTO: %obf.const.pool.base = call ptr @__obf_const_pool_decode_
; AUTO: %slot = getelementptr inbounds [3 x i32], ptr %obf.const.pool.base, i64 0, i64 %wide
