; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/bogus-control-flow-depth3.yaml --obf-seed=1 -passes=obf-bogus-cf -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %opt -passes=verify -disable-output %t
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

; At mba depth 3 the always-true predicate uses affine encode/decode; the branch
; polarity and decoy trap family remain seed-selected (direct or inverted guard;
; decoy loop or straight-line arithmetic chain). The trip count is not pinned.
; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @branchy
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: %obf.opaque.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.opaque.direct = extractvalue { i64, i64 } %obf.opaque.pair, 0
; CHECK: %obf.opaque.indirect = extractvalue { i64, i64 } %obf.opaque.pair, 1
; CHECK: %obf.opaque.entropy.mix{{.*}} = {{.*}} i64 %obf.opaque.direct
; CHECK: %obf.opaque.seed.freeze = freeze i64 %obf.opaque.seed
; CHECK-DAG: %obf.opaque.seed.lhs.mul = mul i64 %obf.opaque.seed.freeze,
; CHECK-DAG: %obf.opaque.seed.rhs.mul = mul i64 %obf.opaque.seed.freeze,
; CHECK: %obf.bogus.true = icmp eq i64
; CHECK: br i1 %obf.bogus.{{(true|false)}},
; CHECK: obf.bogus:
; CHECK: %obf.bogus.seed = load i64, ptr @rt_core_ea
; CHECK: %obf.bogus.{{(state.init|acc0)}} =
