; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml -passes=obf-constant-encode -S %s -o %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml -passes=obf-constant-encode -S %s -o %t.second
; RUN: cmp %t.first %t.second
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml --obf-seed=1 -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=SEED1
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/constant-encode-inline-shapes.yaml --obf-seed=2 -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=SEED2

define i32 @inline_shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  ret i32 %c
}

define i32 @main() {
entry:
  %value = call i32 @inline_shape_mix(i32 7)
  %ok = icmp eq i32 %value, -1157
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @inline_shape_mix(i32 %x)
; CHECK-DAG: %obf.const.seed
; CHECK-DAG: %obf.const.mask.delta
; CHECK-DAG: %obf.const.encoded
; CHECK: ret i32

; SEED1-LABEL: define i32 @inline_shape_mix(i32 %x)
; SEED1-DAG: %obf.const.seed = xor i32 %obf.seed.affine.dec

; SEED2-LABEL: define i32 @inline_shape_mix(i32 %x)
; SEED2-DAG: %obf.const.seed = xor i32 %obf.entangle.xor_masked_pair.unmasked, %obf.mba.zero.linear_equiv_pair
