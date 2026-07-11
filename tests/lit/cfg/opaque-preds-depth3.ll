; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds-depth3.yaml -passes=obf-opaque-preds -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds-depth3.yaml -passes=obf-opaque-preds -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds-depth3.yaml -passes=obf-opaque-preds -S %s -o %t
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

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-LABEL: define i32 @check
; CHECK: %obf.entropy.cache = alloca { i64, i64 }, align 8
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: %obf.opaque.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.opaque.direct = extractvalue { i64, i64 } %obf.opaque.pair, 0
; CHECK: %obf.opaque.indirect = extractvalue { i64, i64 } %obf.opaque.pair, 1
; CHECK: %obf.opaque.entropy.mix{{.*}} = {{.*}}
; CHECK: %obf.opaque.seed =
; CHECK: %obf.opaque.seed.freeze = freeze i64 %obf.opaque.seed
; CHECK-DAG: %obf.opaque.seed.lhs.mul{{[0-9]*}} = mul i64 %obf.opaque.seed.freeze
; CHECK-DAG: %obf.opaque.seed.lhs.mul{{[0-9]*}} = mul i64 %obf.opaque.seed.freeze
; CHECK-DAG: %obf.opaque.seed.lhs.enc{{[0-9]*}} = add i64 %obf.opaque.seed.lhs.mul
; CHECK-DAG: %obf.opaque.seed.lhs.enc{{[0-9]*}} = add i64 %obf.opaque.seed.lhs.mul
; CHECK-DAG: %obf.opaque.seed.lhs.sub{{[0-9]*}} = sub i64 %obf.opaque.seed.lhs.enc
; CHECK-DAG: %obf.opaque.seed.lhs.sub{{[0-9]*}} = sub i64 %obf.opaque.seed.lhs.enc
; CHECK-DAG: %obf.opaque.seed.lhs.dec{{[0-9]*}} = mul i64 %obf.opaque.seed.lhs.sub
; CHECK-DAG: %obf.opaque.seed.lhs.dec{{[0-9]*}} = mul i64 %obf.opaque.seed.lhs.sub
; CHECK-DAG: %obf.opaque.seed.rhs.mul{{[0-9]*}} = mul i64 %obf.opaque.seed.freeze
; CHECK-DAG: %obf.opaque.seed.rhs.mul{{[0-9]*}} = mul i64 %obf.opaque.seed.freeze
; CHECK-DAG: %obf.opaque.seed.rhs.enc{{[0-9]*}} = add i64 %obf.opaque.seed.rhs.mul
; CHECK-DAG: %obf.opaque.seed.rhs.enc{{[0-9]*}} = add i64 %obf.opaque.seed.rhs.mul
; CHECK-DAG: %obf.opaque.seed.rhs.sub{{[0-9]*}} = sub i64 %obf.opaque.seed.rhs.enc
; CHECK-DAG: %obf.opaque.seed.rhs.sub{{[0-9]*}} = sub i64 %obf.opaque.seed.rhs.enc
; CHECK-DAG: %obf.opaque.seed.rhs.dec{{[0-9]*}} = mul i64 %obf.opaque.seed.rhs.sub
; CHECK-DAG: %obf.opaque.seed.rhs.dec{{[0-9]*}} = mul i64 %obf.opaque.seed.rhs.sub
; CHECK-DAG: %obf.opaque.expr.a{{[0-9]*}} =
; CHECK-DAG: %obf.opaque.expr.a{{[0-9]*}} =
; CHECK-DAG: %obf.opaque.expr.b{{[0-9]*}} =
; CHECK-DAG: %obf.opaque.expr.b{{[0-9]*}} =
; CHECK-DAG: %obf.opaque.guard.true = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.false.source = icmp eq i64
; CHECK-DAG: %obf.opaque.guard.false = xor i1 %obf.opaque.guard.false.source
; CHECK-DAG: %obf.opaque.input = freeze i1 %gt
; CHECK-DAG: %obf.opaque.mux.{{(select|and_or)}} =
