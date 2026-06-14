; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o %t.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes=obf-constant-encode -S %s -o %t.second
; RUN: cmp %t.first %t.second

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

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @shape_mix(i32 %x)
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK-COUNT-1: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK-DAG: %obf.entropy.a.mix.a.rot.pack = or i64 %obf.entropy.a.mix.a.rot, %obf.entropy.a.mix.a.rot2
; CHECK-DAG: %obf.entropy.a.mix.rotx = xor i64 %obf.entropy.a.mix.a.rot.pack, %obf.entropy.a.mix.b.rot.pack
; CHECK-DAG: %obf.entropy.b.mix.rotx = xor i64 %obf.entropy.b.mix.a.rot.pack, %obf.entropy.b.mix.b.rot.pack
; CHECK-DAG: obf.mba.zero.xor_pair.delta
; CHECK-DAG: obf.mba.zero.cmp_select_pair
; CHECK-DAG: obf.mba.zero.cmp_select_pair.zero.alt
; CHECK-DAG: obf.mba.zero.rotate_xor_pair
; CHECK-DAG: obf.mba.zero.add_sub_pair
; CHECK-DAG: obf.mba.zero.add_sub_pair.delta
; CHECK-DAG: obf.mba.zero.affine_cancel_pair
; CHECK-DAG: obf.mba.zero.affine_self_diff
; CHECK-DAG: obf.mba.zero.linear_equiv_pair
; CHECK-DAG: obf.mba.add.
; CHECK-DAG: obf.mba.sub.
; CHECK-DAG: obf.mba.xor.
; CHECK-DAG: %obf.seed.zero_add.value = add i32
; CHECK-NOT: obf.mba.zero.poly_binomial
; CHECK-NOT: obf.mba.zero.poly_affine
; CHECK-DAG: obf.entangle.xor_zero.zero
; CHECK: ret i32
