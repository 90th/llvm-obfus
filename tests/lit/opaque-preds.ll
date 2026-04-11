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

; CHECK-LABEL: define i32 @check
; CHECK: %obf.opaque.dec = sub i32 %x, 1
; CHECK: %obf.opaque.mul = mul i32 %x, %obf.opaque.dec
; CHECK: %obf.opaque.and = and i32 %obf.opaque.mul, 1
; CHECK: %obf.opaque.true = icmp eq i32 %obf.opaque.and, 0
; CHECK: %obf.opaque.cond = and i1 %gt, %obf.opaque.true
