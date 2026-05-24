; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  ret i32 %d
}

define i32 @main() {
entry:
  %value = call i32 @shape_mix(i32 7)
  %ok = icmp eq i32 %value, 8842
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @shape_mix(i32 %x)
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK-COUNT-1: call { i64, i64 } @__obf_entropy_thunk_
; CHECK-DAG: obf.mba.zero.xor_pair.delta
; CHECK-DAG: obf.mba.zero.cmp_select_pair
; CHECK-DAG: obf.mba.zero.cmp_select_pair.zero.alt
; CHECK-DAG: obf.mba.zero.rotate_xor_pair
; CHECK-DAG: obf.mba.zero.add_sub_pair
; CHECK-DAG: obf.mba.zero.add_sub_pair.delta
; CHECK-DAG: obf.entangle.xor_zero.zero
; CHECK: ret i32
