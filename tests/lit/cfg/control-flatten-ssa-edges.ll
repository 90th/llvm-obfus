; Edge-shape coverage for dispatcher SSA threading:
;   flat_dupsucc  - a conditional branch with duplicate logical successors,
;   flat_critical - a critical edge (A multi-succ -> D multi-pred) carrying a value,
;   flat_multiexit- a loop with two return blocks and a carried value escaping
;                   into both via non-PHI cross-block uses.
; flat_* are flattened, ref_* are baselines; main returns nonzero on mismatch.

; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=6 -passes='obf-control-flatten,verify' -S %s -o %t6.ll
; RUN: %lli %t6.ll

; CHECK: obf.flat.dispatch:

define i32 @flat_dupsucc(i32 %n) {
entry:
  %d = mul i32 %n, 2
  %c = icmp sgt i32 %n, 3
  br i1 %c, label %mid, label %mid
mid:
  %p = phi i32 [ %d, %entry ], [ %d, %entry ]
  %e = add i32 %p, 1
  %c2 = icmp sgt i32 %e, 20
  br i1 %c2, label %hi, label %lo
hi:
  ret i32 %e
lo:
  ret i32 %p
}
define i32 @ref_dupsucc(i32 %n) {
entry:
  %d = mul i32 %n, 2
  %c = icmp sgt i32 %n, 3
  br i1 %c, label %mid, label %mid
mid:
  %p = phi i32 [ %d, %entry ], [ %d, %entry ]
  %e = add i32 %p, 1
  %c2 = icmp sgt i32 %e, 20
  br i1 %c2, label %hi, label %lo
hi:
  ret i32 %e
lo:
  ret i32 %p
}

define i32 @flat_critical(i32 %n) {
entry:
  %c1 = icmp sgt i32 %n, 5
  br i1 %c1, label %A, label %D
A:
  %av = mul i32 %n, 2
  %c2 = icmp sgt i32 %n, 10
  br i1 %c2, label %D, label %E
E:
  br label %exit
D:
  %p = phi i32 [ %n, %entry ], [ %av, %A ]
  br label %exit
exit:
  %r = phi i32 [ %p, %D ], [ 7, %E ]
  ret i32 %r
}
define i32 @ref_critical(i32 %n) {
entry:
  %c1 = icmp sgt i32 %n, 5
  br i1 %c1, label %A, label %D
A:
  %av = mul i32 %n, 2
  %c2 = icmp sgt i32 %n, 10
  br i1 %c2, label %D, label %E
E:
  br label %exit
D:
  %p = phi i32 [ %n, %entry ], [ %av, %A ]
  br label %exit
exit:
  %r = phi i32 [ %p, %D ], [ 7, %E ]
  ret i32 %r
}

define i32 @flat_multiexit(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %latch ]
  %s = phi i32 [ 0, %entry ], [ %s.next, %latch ]
  %i.next = add i32 %i, 1
  %s.next = add i32 %s, %i.next
  %hit = icmp sgt i32 %s.next, 20
  br i1 %hit, label %early, label %cont
cont:
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %late, label %latch
latch:
  br label %loop
early:
  ret i32 %s.next
late:
  ret i32 %s.next
}
define i32 @ref_multiexit(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %latch ]
  %s = phi i32 [ 0, %entry ], [ %s.next, %latch ]
  %i.next = add i32 %i, 1
  %s.next = add i32 %s, %i.next
  %hit = icmp sgt i32 %s.next, 20
  br i1 %hit, label %early, label %cont
cont:
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %late, label %latch
latch:
  br label %loop
early:
  ret i32 %s.next
late:
  ret i32 %s.next
}

define i32 @main() {
entry:
  br label %loop
loop:
  %n = phi i32 [ 1, %entry ], [ %n.next, %loop ]
  %bad = phi i32 [ 0, %entry ], [ %bad.next, %loop ]
  %f1 = call i32 @flat_dupsucc(i32 %n)
  %r1 = call i32 @ref_dupsucc(i32 %n)
  %d1 = icmp ne i32 %f1, %r1
  %f2 = call i32 @flat_critical(i32 %n)
  %r2 = call i32 @ref_critical(i32 %n)
  %d2 = icmp ne i32 %f2, %r2
  %f3 = call i32 @flat_multiexit(i32 %n)
  %r3 = call i32 @ref_multiexit(i32 %n)
  %d3 = icmp ne i32 %f3, %r3
  %o1 = or i1 %d1, %d2
  %o2 = or i1 %o1, %d3
  %z = zext i1 %o2 to i32
  %bad.next = add i32 %bad, %z
  %n.next = add i32 %n, 1
  %done = icmp eq i32 %n.next, 20
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %bad.next
}
