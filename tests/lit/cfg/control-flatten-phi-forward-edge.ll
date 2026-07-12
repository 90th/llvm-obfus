; Regression fixture for the dispatcher-PHI mutation-before-read hazard in
; control flattening (forward/exit-edge capture of a carried value).
;
; %i.next is defined in the loop block `s` and (1) feeds the same-block PHI %i,
; forcing it into carried_values, and (2) is %m's incoming operand on the FORWARD
; loop-exit edge s->t. Before the fix, the use-replacement pass overwrote %m's
; operand with the dispatcher PHI, and translate_value_for_edge then threaded that
; dispatcher PHI (a same-block value, stale by one dispatch iteration) instead of
; the fresh %i.next -> flattened result was off by one while `opt -passes=verify`
; stayed happy. flat_forward is flattened; ref_forward is the untouched baseline;
; main returns nonzero on any mismatch, so `%lli` exiting 0 IS the assertion.
;
; This fixture FAILS on the pre-fix pass (flat=n-1 vs ref=n) and PASSES after it.

; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.s1.ll
; RUN: %FileCheck %s < %t.s1.ll
; RUN: %opt -passes=verify -disable-output %t.s1.ll
; RUN: %lli %t.s1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=7 -passes='obf-control-flatten,verify' -S %s -o %t.s7.ll
; RUN: %lli %t.s7.ll
; RUN: %opt -passes='default<O2>' -S %t.s1.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
; RUN: %opt -passes='default<O3>' -S %t.s1.ll -o %t.o3.ll
; RUN: %lli %t.o3.ll

; CHECK-LABEL: define i32 @flat_forward
; CHECK: obf.flat.dispatch:
; CHECK: %obf.flat.val = phi
; CHECK-LABEL: define i32 @ref_forward

define i32 @flat_forward(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %i.next, %s ]
  ret i32 %m
}

define i32 @ref_forward(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %i.next, %s ]
  ret i32 %m
}

define i32 @main() {
entry:
  br label %loop
loop:
  %n = phi i32 [ 2, %entry ], [ %n.next, %loop ]
  %bad = phi i32 [ 0, %entry ], [ %bad.acc, %loop ]
  %f = call i32 @flat_forward(i32 %n)
  %r = call i32 @ref_forward(i32 %n)
  %ne = icmp ne i32 %f, %r
  %ne.z = zext i1 %ne to i32
  %bad.acc = add i32 %bad, %ne.z
  %n.next = add i32 %n, 1
  %done = icmp eq i32 %n.next, 12
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %bad.acc
}
