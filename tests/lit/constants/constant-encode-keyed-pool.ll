; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @repeated(i32 %x) {
entry:
  %a = add i32 %x, 31337
  %b = xor i32 %a, 31337
  %c = add i32 %b, 31337
  ret i32 %c
}

define i32 @main() {
entry:
  %value = call i32 @repeated(i32 5)
  %ok = icmp eq i32 %value, 31344
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: @__obf_const_pool_
; CHECK: @__obf_const_desc_
; CHECK: @__obf_const_destination_ref_
; CHECK: @__obf_const_ciphertext_ref_
; CHECK: @__obf_const_build_key_ref_
; CHECK: @__obf_const_state_ref_
; CHECK-LABEL: define i32 @repeated(i32 %x) {
; CHECK: %obf.const.pool.base = call ptr @__obf_const_pool_decode_
; CHECK: %obf.const.pool.load = load i32, ptr %obf.const.pool.ptr
; CHECK-LABEL: define internal ptr @__obf_const_pool_decode_
; CHECK: call ptr @rt_core_cpd2(ptr @__obf_const_desc_
; CHECK-NOT: %obf.const.mask =
