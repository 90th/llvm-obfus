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
  %positive = call i32 @check(i32 9)
  %positive.ok = icmp eq i32 %positive, 1
  %negative = call i32 @check(i32 1)
  %negative.ok = icmp eq i32 %negative, 0
  %both = and i1 %positive.ok, %negative.ok
  %ret = select i1 %both, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @check
; CHECK: %obf.opaque.seed =
; CHECK: %obf.opaque.expr.a =
; CHECK: %obf.opaque.expr.b =
; CHECK: %obf.opaque.true = icmp eq i64 %obf.opaque.expr.a, %obf.opaque.expr.b
