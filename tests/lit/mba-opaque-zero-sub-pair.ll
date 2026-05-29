; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml --obf-seed=1 -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml --obf-seed=1 -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml --obf-seed=1 -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  ret i32 %c
}

define i32 @main() {
entry:
  %value = call i32 @shape_mix(i32 7)
  %ok = icmp eq i32 %value, -1157
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @shape_mix(i32 %x)
; CHECK: %obf.mba.zero.sub_pair.delta = xor i32
; CHECK: %obf.mba.zero.sub_pair.masked = xor i32
; CHECK: %obf.mba.zero.sub_pair.unmasked = xor i32
; CHECK: %obf.mba.zero.sub_pair = sub i32 %obf.mba.zero.sub_pair.unmasked, %obf.mba.zero.sub_pair.delta
; CHECK: %obf.mba.zero.affine_cancel_pair.term = xor i32
; CHECK: %obf.mba.xor.affine.or.mul = mul i32
