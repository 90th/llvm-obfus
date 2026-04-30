; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o %t
; RUN: %lli %t

define i32 @branchy(i32 %x) {
entry:
  %is_zero = icmp eq i32 %x, 0
  br i1 %is_zero, label %zero, label %nonzero

zero:
  ret i32 7

nonzero:
  br label %merge

merge:
  ret i32 %x
}

define i32 @main() {
entry:
  %value = call i32 @branchy(i32 5)
  %ok = icmp eq i32 %value, 5
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @branchy
; CHECK: %obf.opaque.entropy = load i64, ptr @__obf_entropy_anchor
; CHECK: [[EXPRA:%obf\.opaque\.expr\.a[^ ]*]] = {{(add|or|sub|xor) i64}}
; CHECK: [[EXPRB:%obf\.opaque\.expr\.b[^ ]*]] = {{(add|or|sub|xor) i64}}
; CHECK: %obf.opaque.true = icmp eq i64 [[EXPRA]], [[EXPRB]]
; CHECK: br i1 %obf.opaque.true, label %merge, label %obf.bogus
; CHECK: obf.bogus:
; CHECK: %obf.bogus.seed = load i64, ptr @__obf_entropy_anchor
; CHECK: br label %obf.bogus.loop
; CHECK: obf.bogus.loop:
; CHECK: %obf.bogus.iter = phi i32
; CHECK: %obf.bogus.state = phi i64
; CHECK: %obf.bogus.rotl.shl = shl i64 %obf.bogus.state, 13
; CHECK: %obf.bogus.rotl.lshr = lshr i64 %obf.bogus.state, 51
; CHECK: %obf.bogus.mix = xor i64 %obf.bogus.rotl,
; CHECK: %obf.bogus.iter.next = add i32 %obf.bogus.iter, 1
; CHECK: %obf.bogus.done = icmp eq i32 %obf.bogus.iter.next, 1000000
; CHECK: br i1 %obf.bogus.done, label %obf.bogus.sink, label %obf.bogus.loop
; CHECK-NOT: %obf.opaque.dec =
; CHECK-NOT: %obf.opaque.mul =
; CHECK-NOT: %obf.opaque.and =
; CHECK-NOT: %obf.bogus.xor =
