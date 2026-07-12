; Diamond with a dual-use value inside a loop.
; %v is defined in `s` (a diamond arm) and (1) is consumed by a non-PHI
; cross-block instruction %vsink in `extra` (dominated by s) -> forced into
; carried_values, and (2) is %m's incoming operand on the forward edge s->join.
; Because %v is defined in the edge-source block, the pre-fix pass threaded the
; stale dispatcher PHI into %m; the SSA plan now threads the fresh %v.
; flat_* is flattened, ref_* is baseline; main returns nonzero on mismatch.

; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=5 -passes='obf-control-flatten,verify' -S %s -o %t5.ll
; RUN: %lli %t5.ll

; CHECK: obf.flat.dispatch:

define i32 @flat_diamond(i32 %n) {
entry:
  br label %header
header:
  %i = phi i32 [ 1, %entry ], [ %i.next, %join ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %join ]
  %i.next = add i32 %i, 1
  %par = and i32 %i, 1
  %c = icmp ne i32 %par, 0
  br i1 %c, label %s, label %join
s:
  %v = mul i32 %i, 3
  %never = icmp eq i32 %i, -1
  br i1 %never, label %extra, label %join
extra:
  %vsink = add i32 %v, 100
  br label %join
join:
  %m = phi i32 [ %v, %s ], [ %vsink, %extra ], [ 0, %header ]
  %acc.next = add i32 %acc, %m
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %exit, label %header
exit:
  ret i32 %acc
}

define i32 @ref_diamond(i32 %n) {
entry:
  br label %header
header:
  %i = phi i32 [ 1, %entry ], [ %i.next, %join ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %join ]
  %i.next = add i32 %i, 1
  %par = and i32 %i, 1
  %c = icmp ne i32 %par, 0
  br i1 %c, label %s, label %join
s:
  %v = mul i32 %i, 3
  %never = icmp eq i32 %i, -1
  br i1 %never, label %extra, label %join
extra:
  %vsink = add i32 %v, 100
  br label %join
join:
  %m = phi i32 [ %v, %s ], [ %vsink, %extra ], [ 0, %header ]
  %acc.next = add i32 %acc, %m
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %exit, label %header
exit:
  ret i32 %acc
}

define i32 @main() {
entry:
  br label %loop
loop:
  %n = phi i32 [ 2, %entry ], [ %n.next, %loop ]
  %bad = phi i32 [ 0, %entry ], [ %bad.acc, %loop ]
  %f = call i32 @flat_diamond(i32 %n)
  %r = call i32 @ref_diamond(i32 %n)
  %ne = icmp ne i32 %f, %r
  %ne.z = zext i1 %ne to i32
  %bad.acc = add i32 %bad, %ne.z
  %n.next = add i32 %n, 1
  %done = icmp eq i32 %n.next, 16
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %bad.acc
}
