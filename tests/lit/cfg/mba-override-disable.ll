; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-override-disable.yaml -passes=obf-opaque-preds -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-override-disable.yaml -passes=obf-opaque-preds -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-override-disable.yaml -passes=obf-opaque-preds -S %s -o %t
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

; at depth 3 with polynomial disabled, the opaque predicate must still
; be emitted and must preserve branch behavior
; CHECK: %obf.opaque.pair = load
; CHECK: %obf.opaque.entropy.mix{{.*}} = {{.*}}
; CHECK: %obf.opaque.guard.true = icmp eq i64 %obf.opaque.expr.a, %obf.opaque.expr.b

