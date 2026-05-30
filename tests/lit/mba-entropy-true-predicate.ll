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
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: %obf.entropy.cache.init = call { i64, i64 } @__obf_entropy_thunk_
; CHECK: %obf.opaque.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.opaque.direct = extractvalue { i64, i64 } %obf.opaque.pair, 0
; CHECK: %obf.opaque.indirect = extractvalue { i64, i64 } %obf.opaque.pair, 1
; CHECK: %obf.opaque.entropy.mix = xor i64 %obf.opaque.direct, %obf.opaque.indirect
; CHECK: %obf.opaque.seed =
; CHECK: %obf.opaque.seed.freeze = freeze i64 %obf.opaque.seed
; CHECK: %obf.opaque.expr.a =
; CHECK: %obf.opaque.expr.b =
; CHECK: %obf.opaque.true = icmp eq i64 %obf.opaque.expr.a, %obf.opaque.expr.b
