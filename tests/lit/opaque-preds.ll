; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-preds.yaml -passes=obf-opaque-preds -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-preds.yaml -passes=obf-opaque-preds -S %s -o %t
; RUN: %lli %t

define i32 @check(i32 %x) {
entry:
  %gt = icmp sgt i32 %x, 3
  br i1 %gt, label %yes, label %no

yes:
  ret i32 1

no:
  ret i32 0
}

define i32 @main() {
entry:
  %v = call i32 @check(i32 9)
  %ok = icmp eq i32 %v, 1
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK-LABEL: define i32 @check
; CHECK: %obf.opaque.entropy = load i64, ptr @__obf_entropy_anchor
; CHECK: [[EXPRA:%obf\.opaque\.expr\.a[^ ]*]] = {{(add|sub|xor) i64}}
; CHECK: [[EXPRB:%obf\.opaque\.expr\.b[^ ]*]] = {{(add|sub|xor) i64}}
; CHECK: %obf.opaque.true = icmp eq i64 [[EXPRA]], [[EXPRB]]
; CHECK: %obf.opaque.cond = and i1 %gt, %obf.opaque.true
; CHECK-NOT: %obf.opaque.dec =
; CHECK-NOT: %obf.opaque.mul =
; CHECK-NOT: %obf.opaque.and =
