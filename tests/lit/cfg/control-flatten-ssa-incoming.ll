; Incoming-value variety threaded across the dispatcher: constant, argument,
; instruction, poison (on an untaken edge), and frozen instruction. Each captures
; its value through an original PHI whose operand the pre-fix pass would clobber.
; flat_* are flattened, ref_* are baselines; main returns nonzero on mismatch.

; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=4 -passes='obf-control-flatten,verify' -S %s -o %t4.ll
; RUN: %lli %t4.ll

; CHECK: obf.flat.dispatch:

; --- constant incoming ---
define i32 @flat_const(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ 42, %s ]
  ret i32 %m
}
define i32 @ref_const(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ 42, %s ]
  ret i32 %m
}

; --- argument incoming ---
define i32 @flat_arg(i32 %n, i32 %a) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %a, %s ]
  ret i32 %m
}
define i32 @ref_arg(i32 %n, i32 %a) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %a, %s ]
  ret i32 %m
}

; --- instruction incoming (the fixed hazard) ---
define i32 @flat_inst(i32 %n) {
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
define i32 @ref_inst(i32 %n) {
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

; --- poison incoming on a statically-present but untaken edge ---
define i32 @flat_poison(i32 %n) {
entry:
  br label %pre
pre:
  %guard = icmp sgt i32 %n, 100000
  br i1 %guard, label %poisonsrc, label %s
poisonsrc:
  br label %t
s:
  %i = phi i32 [ 0, %pre ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ poison, %poisonsrc ], [ %i.next, %s ]
  ret i32 %m
}
define i32 @ref_poison(i32 %n) {
entry:
  br label %pre
pre:
  %guard = icmp sgt i32 %n, 100000
  br i1 %guard, label %poisonsrc, label %s
poisonsrc:
  br label %t
s:
  %i = phi i32 [ 0, %pre ], [ %i.next, %s ]
  %i.next = add i32 %i, 1
  %cont = icmp slt i32 %i.next, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ poison, %poisonsrc ], [ %i.next, %s ]
  ret i32 %m
}

; --- frozen-instruction incoming (freeze feeds the loop carry -> carried) ---
define i32 @flat_frozen(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %fr, %s ]
  %step = add i32 %i, 1
  %fr = freeze i32 %step
  %cont = icmp slt i32 %fr, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %fr, %s ]
  ret i32 %m
}
define i32 @ref_frozen(i32 %n) {
entry:
  br label %s
s:
  %i = phi i32 [ 0, %entry ], [ %fr, %s ]
  %step = add i32 %i, 1
  %fr = freeze i32 %step
  %cont = icmp slt i32 %fr, %n
  br i1 %cont, label %s, label %t
t:
  %m = phi i32 [ %fr, %s ]
  ret i32 %m
}

define i32 @main() {
entry:
  br label %loop
loop:
  %n = phi i32 [ 2, %entry ], [ %n.next, %loop ]
  %bad = phi i32 [ 0, %entry ], [ %bad.next, %loop ]
  %arg = mul i32 %n, 7
  %f1 = call i32 @flat_const(i32 %n)
  %r1 = call i32 @ref_const(i32 %n)
  %d1 = icmp ne i32 %f1, %r1
  %f2 = call i32 @flat_arg(i32 %n, i32 %arg)
  %r2 = call i32 @ref_arg(i32 %n, i32 %arg)
  %d2 = icmp ne i32 %f2, %r2
  %f3 = call i32 @flat_inst(i32 %n)
  %r3 = call i32 @ref_inst(i32 %n)
  %d3 = icmp ne i32 %f3, %r3
  %f4 = call i32 @flat_poison(i32 %n)
  %r4 = call i32 @ref_poison(i32 %n)
  %d4 = icmp ne i32 %f4, %r4
  %f5 = call i32 @flat_frozen(i32 %n)
  %r5 = call i32 @ref_frozen(i32 %n)
  %d5 = icmp ne i32 %f5, %r5
  %o1 = or i1 %d1, %d2
  %o2 = or i1 %o1, %d3
  %o3 = or i1 %o2, %d4
  %o4 = or i1 %o3, %d5
  %z = zext i1 %o4 to i32
  %bad.next = add i32 %bad, %z
  %n.next = add i32 %n, 1
  %done = icmp eq i32 %n.next, 14
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %bad.next
}
