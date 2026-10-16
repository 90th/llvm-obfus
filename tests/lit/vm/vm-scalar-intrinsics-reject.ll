; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-scalar-intrinsics.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status] | join("|")' | %FileCheck %s
;
; Scalar synthesis must reject vectors and types beyond its widening limit.
; Ordered comparisons need one extra bit. Full products need twice the width.

declare <2 x i8> @llvm.abs.v2i8(<2 x i8>, i1 immarg)
declare <2 x i32> @llvm.scmp.v2i32.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i2> @llvm.ucmp.v2i2.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.uadd.sat.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.usub.sat.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.sadd.sat.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.ssub.sat.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.uadd.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.sadd.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.usub.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.ssub.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.umul.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare { <2 x i8>, <2 x i1> } @llvm.smul.with.overflow.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.expect.v2i8(<2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.expect.with.probability.v2i8(<2 x i8>, <2 x i8>, double immarg)

define <2 x i8> @vm_scalar_vector_abs(<2 x i8> %a) {
  %result = call <2 x i8> @llvm.abs.v2i8(<2 x i8> %a, i1 false)
  ret <2 x i8> %result
}
define <2 x i32> @vm_scalar_vector_scmp(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i32> @llvm.scmp.v2i32.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i32> %result
}
define <2 x i2> @vm_scalar_vector_ucmp(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i2> @llvm.ucmp.v2i2.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i2> %result
}
define <2 x i8> @vm_scalar_vector_uadd_sat(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.uadd.sat.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i8> %result
}
define <2 x i8> @vm_scalar_vector_usub_sat(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.usub.sat.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i8> %result
}
define <2 x i8> @vm_scalar_vector_sadd_sat(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.sadd.sat.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i8> %result
}
define <2 x i8> @vm_scalar_vector_ssub_sat(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.ssub.sat.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i8> %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_uadd_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.uadd.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_sadd_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.sadd.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_usub_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.usub.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_ssub_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.ssub.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_umul_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.umul.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}
define { <2 x i8>, <2 x i1> } @vm_scalar_vector_smul_overflow(<2 x i8> %a, <2 x i8> %b) {
  %result = call { <2 x i8>, <2 x i1> } @llvm.smul.with.overflow.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret { <2 x i8>, <2 x i1> } %result
}

define <2 x i8> @vm_scalar_vector_expect(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.expect.v2i8(<2 x i8> %a, <2 x i8> %b)
  ret <2 x i8> %result
}
define <2 x i8> @vm_scalar_vector_probability(<2 x i8> %a, <2 x i8> %b) {
  %result = call <2 x i8> @llvm.expect.with.probability.v2i8(<2 x i8> %a, <2 x i8> %b, double 5.000000e-01)
  ret <2 x i8> %result
}

declare i8388608 @llvm.abs.i8388608(i8388608, i1 immarg)
declare i32 @llvm.scmp.i32.i8388608(i8388608, i8388608)
declare i2 @llvm.ucmp.i2.i8388608(i8388608, i8388608)
declare i8388608 @llvm.uadd.sat.i8388608(i8388608, i8388608)
declare i8388608 @llvm.usub.sat.i8388608(i8388608, i8388608)
declare i8388608 @llvm.sadd.sat.i8388608(i8388608, i8388608)
declare i8388608 @llvm.ssub.sat.i8388608(i8388608, i8388608)
declare { i8388608, i1 } @llvm.uadd.with.overflow.i8388608(i8388608, i8388608)
declare { i8388608, i1 } @llvm.sadd.with.overflow.i8388608(i8388608, i8388608)
declare { i8388608, i1 } @llvm.usub.with.overflow.i8388608(i8388608, i8388608)
declare { i8388608, i1 } @llvm.ssub.with.overflow.i8388608(i8388608, i8388608)
declare { i4194305, i1 } @llvm.umul.with.overflow.i4194305(i4194305, i4194305)
declare { i4194305, i1 } @llvm.smul.with.overflow.i4194305(i4194305, i4194305)

define i8388608 @vm_scalar_wide_abs(i8388608 %a) {
  %result = call i8388608 @llvm.abs.i8388608(i8388608 %a, i1 false)
  ret i8388608 %result
}
define i32 @vm_scalar_wide_scmp(i8388608 %a, i8388608 %b) {
  %result = call i32 @llvm.scmp.i32.i8388608(i8388608 %a, i8388608 %b)
  ret i32 %result
}
define i2 @vm_scalar_wide_ucmp(i8388608 %a, i8388608 %b) {
  %result = call i2 @llvm.ucmp.i2.i8388608(i8388608 %a, i8388608 %b)
  ret i2 %result
}
define i8388608 @vm_scalar_wide_uadd_sat(i8388608 %a, i8388608 %b) {
  %result = call i8388608 @llvm.uadd.sat.i8388608(i8388608 %a, i8388608 %b)
  ret i8388608 %result
}
define i8388608 @vm_scalar_wide_usub_sat(i8388608 %a, i8388608 %b) {
  %result = call i8388608 @llvm.usub.sat.i8388608(i8388608 %a, i8388608 %b)
  ret i8388608 %result
}
define i8388608 @vm_scalar_wide_sadd_sat(i8388608 %a, i8388608 %b) {
  %result = call i8388608 @llvm.sadd.sat.i8388608(i8388608 %a, i8388608 %b)
  ret i8388608 %result
}
define i8388608 @vm_scalar_wide_ssub_sat(i8388608 %a, i8388608 %b) {
  %result = call i8388608 @llvm.ssub.sat.i8388608(i8388608 %a, i8388608 %b)
  ret i8388608 %result
}
define { i8388608, i1 } @vm_scalar_wide_uadd_overflow(i8388608 %a, i8388608 %b) {
  %result = call { i8388608, i1 } @llvm.uadd.with.overflow.i8388608(i8388608 %a, i8388608 %b)
  ret { i8388608, i1 } %result
}
define { i8388608, i1 } @vm_scalar_wide_sadd_overflow(i8388608 %a, i8388608 %b) {
  %result = call { i8388608, i1 } @llvm.sadd.with.overflow.i8388608(i8388608 %a, i8388608 %b)
  ret { i8388608, i1 } %result
}
define { i8388608, i1 } @vm_scalar_wide_usub_overflow(i8388608 %a, i8388608 %b) {
  %result = call { i8388608, i1 } @llvm.usub.with.overflow.i8388608(i8388608 %a, i8388608 %b)
  ret { i8388608, i1 } %result
}
define { i8388608, i1 } @vm_scalar_wide_ssub_overflow(i8388608 %a, i8388608 %b) {
  %result = call { i8388608, i1 } @llvm.ssub.with.overflow.i8388608(i8388608 %a, i8388608 %b)
  ret { i8388608, i1 } %result
}
define { i4194305, i1 } @vm_scalar_wide_umul_overflow(i4194305 %a, i4194305 %b) {
  %result = call { i4194305, i1 } @llvm.umul.with.overflow.i4194305(i4194305 %a, i4194305 %b)
  ret { i4194305, i1 } %result
}
define { i4194305, i1 } @vm_scalar_wide_smul_overflow(i4194305 %a, i4194305 %b) {
  %result = call { i4194305, i1 } @llvm.smul.with.overflow.i4194305(i4194305 %a, i4194305 %b)
  ret { i4194305, i1 } %result
}

; CHECK-DAG: vm_scalar_vector_abs|not_candidate
; CHECK-DAG: vm_scalar_vector_scmp|not_candidate
; CHECK-DAG: vm_scalar_vector_ucmp|not_candidate
; CHECK-DAG: vm_scalar_vector_uadd_sat|not_candidate
; CHECK-DAG: vm_scalar_vector_usub_sat|not_candidate
; CHECK-DAG: vm_scalar_vector_sadd_sat|not_candidate
; CHECK-DAG: vm_scalar_vector_ssub_sat|not_candidate
; CHECK-DAG: vm_scalar_vector_uadd_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_sadd_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_usub_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_ssub_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_umul_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_smul_overflow|not_candidate
; CHECK-DAG: vm_scalar_vector_expect|not_candidate
; CHECK-DAG: vm_scalar_vector_probability|not_candidate
; CHECK-DAG: vm_scalar_wide_abs|not_candidate
; CHECK-DAG: vm_scalar_wide_scmp|not_candidate
; CHECK-DAG: vm_scalar_wide_ucmp|not_candidate
; CHECK-DAG: vm_scalar_wide_uadd_sat|not_candidate
; CHECK-DAG: vm_scalar_wide_usub_sat|not_candidate
; CHECK-DAG: vm_scalar_wide_sadd_sat|not_candidate
; CHECK-DAG: vm_scalar_wide_ssub_sat|not_candidate
; CHECK-DAG: vm_scalar_wide_uadd_overflow|not_candidate
; CHECK-DAG: vm_scalar_wide_sadd_overflow|not_candidate
; CHECK-DAG: vm_scalar_wide_usub_overflow|not_candidate
; CHECK-DAG: vm_scalar_wide_ssub_overflow|not_candidate
; CHECK-DAG: vm_scalar_wide_umul_overflow|not_candidate
; CHECK-DAG: vm_scalar_wide_smul_overflow|not_candidate
