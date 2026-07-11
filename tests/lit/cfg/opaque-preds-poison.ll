; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds.yaml --obf-seed=1 -passes=obf-opaque-preds -S - -o %t.seed1.first < %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds.yaml --obf-seed=1 -passes=obf-opaque-preds -S - -o %t.seed1.second < %s
; RUN: cmp %t.seed1.first %t.seed1.second
; RUN: %FileCheck %s --check-prefix=SEED1 < %t.seed1.first
; RUN: %opt -passes=verify -disable-output %t.seed1.first
; RUN: %lli %t.seed1.first
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-preds.yaml --obf-seed=3 -passes=obf-opaque-preds -S - -o %t.seed3 < %s
; RUN: %FileCheck %s --check-prefix=SEED3 < %t.seed3
; RUN: %opt -passes=verify -disable-output %t.seed3
; RUN: %lli %t.seed3

define i32 @check(i1 %condition) {
entry:
  br i1 %condition, label %yes, label %no

yes:
  ret i32 1

no:
  ret i32 0
}

define i32 @main() {
entry:
  %true.result = call i32 @check(i1 true)
  %true.ok = icmp eq i32 %true.result, 1
  %false.result = call i32 @check(i1 false)
  %false.ok = icmp eq i32 %false.result, 0
  %ok = and i1 %true.ok, %false.ok
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}

; SEED1-LABEL: define i32 @check(i1 %condition)
; SEED1: [[INPUT:%obf\.opaque\.input]] = freeze i1 %condition
; SEED1-NOT: obf.opaque.input.inverted
; SEED1: [[TRUE_ARM:%obf\.opaque\.mux\.true]] = and i1 [[INPUT]], %obf.opaque.guard.true
; SEED1: [[INVERTED:%[0-9]+]] = xor i1 [[INPUT]], true
; SEED1: [[FALSE_ARM:%obf\.opaque\.mux\.false]] = and i1 [[INVERTED]], %obf.opaque.guard.false
; SEED1: %obf.opaque.mux.and_or = or i1 [[TRUE_ARM]], [[FALSE_ARM]]
; SEED1: br i1 %obf.opaque.mux.and_or, label %yes, label %no

; SEED3-LABEL: define i32 @check(i1 %condition)
; SEED3: [[INPUT:%obf\.opaque\.input]] = freeze i1 %condition
; SEED3: [[INVERTED:%obf\.opaque\.input\.inverted]] = xor i1 [[INPUT]], true
; SEED3: %obf.opaque.mux.select = select i1 [[INVERTED]], i1 %obf.opaque.guard.true, i1 %obf.opaque.guard.false
; SEED3: br i1 %obf.opaque.mux.select, label %no, label %yes
