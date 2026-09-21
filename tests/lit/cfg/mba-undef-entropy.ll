; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-depth3-polynomial.yaml -passes=obf-constant-encode -S %s -o %t.raw.ll
; RUN: %FileCheck %s --check-prefix=STRUCT < %t.raw.ll
; RUN: %opt -passes=verify -disable-output %t.raw.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.raw.ll -o %t.instcombine.ll
; RUN: %opt -O2 -S %t.raw.ll -o %t.o2.ll
; RUN: %FileCheck %s --check-prefix=O2 < %t.o2.ll
;
; Opaque-zero entropy is obfuscator-owned. Even if an accessor returns undef,
; every zero family must remain zero and must not introduce poison.
;
; STRUCT-LABEL: define i32 @poly_shape_mix(i32 %x)
; STRUCT: %obf.mba.zero.input.a{{[0-9]*}} = freeze i32
; STRUCT: %obf.mba.zero.input.b{{[0-9]*}} = freeze i32
; STRUCT-DAG: obf.mba.zero.poly_binomial
; STRUCT-DAG: obf.mba.zero.poly_affine
; O2-LABEL: define {{.*}}i32 @main()
; O2: ret i32 0

define { i64, i64 } @rt_core_ep0() {
  ret { i64, i64 } undef
}

define { i64, i64 } @rt_core_ep1() {
  ret { i64, i64 } undef
}

define { i64, i64 } @rt_core_ep2() {
  ret { i64, i64 } undef
}

define { i64, i64 } @rt_core_ep3() {
  ret { i64, i64 } undef
}

define { i64, i64 } @rt_core_ep4() {
  ret { i64, i64 } undef
}

define i32 @poly_shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  ret i32 %d
}

define i32 @main() {
entry:
  %value = call i32 @poly_shape_mix(i32 7)
  %ok = icmp eq i32 %value, 8842
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
