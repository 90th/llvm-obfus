; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/bogus-control-flow.yaml -passes=obf-bogus-cf -S %s -o %t
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

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @branchy
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: %obf.opaque.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.opaque.direct = extractvalue { i64, i64 } %obf.opaque.pair, 0
; CHECK: %obf.opaque.indirect = extractvalue { i64, i64 } %obf.opaque.pair, 1
; CHECK: %obf.opaque.entropy.mix{{.*}} = {{.*}} i64 %obf.opaque.direct
; CHECK: %obf.opaque.seed =
; CHECK: %obf.opaque.seed.freeze = freeze i64 %obf.opaque.seed
; CHECK: [[EXPRA:%obf\.opaque\.expr\.a[^ ]*]] =
; CHECK: [[EXPRB:%obf\.opaque\.expr\.b[^ ]*]] =
; CHECK: %obf.bogus.true = icmp eq i64 [[EXPRA]], [[EXPRB]]
; CHECK: br i1 %obf.bogus.true, label %merge, label %obf.bogus
; CHECK: obf.bogus:
; CHECK: %obf.bogus.seed = load i64, ptr @rt_core_ea
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
; CHECK-NOT: %obf.bogus.xor =
