; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-all.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=ALL
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-all.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @all_mix(i32 %x) {
entry:
  %a = add i32 %x, 9
  %b = xor i32 %a, 42
  %c = add i32 %b, 31337
  %d = xor i32 %c, 31337
  ret i32 %d
}

define i32 @main() {
entry:
  %value = call i32 @all_mix(i32 5)
  %ok = icmp eq i32 %value, 228
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; ALL: @__obf_const_pool_
; ALL-LABEL: define i32 @all_mix(i32 %x) {
; ALL: %obf.const.mask = {{(add|sub) i32}}
; ALL: %a = add i32 %x, %obf.const
; ALL: %b = xor i32 %a, %obf.const{{[0-9]*}}
; ALL: %obf.const.pool.base = call ptr @__obf_const_pool_decode_
; ALL: %c = add i32 %b, %obf.const.pool.load
; ALL: %d = xor i32 %c, %obf.const.pool.load{{[0-9]+}}
