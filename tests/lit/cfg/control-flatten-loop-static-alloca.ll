; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.s1.ll
; RUN: %FileCheck %s < %t.s1.ll
; RUN: %opt -passes=verify -disable-output %t.s1.ll
; RUN: %lli %t.s1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=99 -passes='obf-control-flatten,verify' -S %s -o %t.s99.ll
; RUN: %lli %t.s99.ll

; CHECK-LABEL: define i32 @flat_loop_alloca
; CHECK: obf.flat.setup:
; CHECK: alloca
; CHECK: obf.flat.dispatch:

; Regression fixture for static alloca hoisting in flattened loops:
; %acc is allocated in entry. It must be hoisted to setup before the dispatcher,
; dominating all uses across loop iterations, without re-allocating inside the dispatcher.
define i32 @flat_loop_alloca(i32 %limit) {
entry:
  %acc = alloca i32, align 4
  store i32 0, ptr %acc, align 4
  br label %loop

loop:
  %i = phi i32 [ 1, %entry ], [ %i.next, %loop.body ]
  %done = icmp sgt i32 %i, %limit
  br i1 %done, label %exit, label %loop.body

loop.body:
  %curr = load i32, ptr %acc, align 4
  %sum = add i32 %curr, %i
  store i32 %sum, ptr %acc, align 4
  %i.next = add i32 %i, 1
  br label %loop

exit:
  %final = load i32, ptr %acc, align 4
  ret i32 %final
}

define i32 @main() {
entry:
  ; sum(1..10) = 55
  %res = call i32 @flat_loop_alloca(i32 10)
  %ok = icmp eq i32 %res, 55
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
