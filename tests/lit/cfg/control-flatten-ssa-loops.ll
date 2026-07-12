; Loop-carried SSA shapes threaded across the dispatcher:
;   flat_indacc  - induction PHI + separate accumulator PHI, accumulator captured
;                  on the forward exit edge (exercises the fixed hazard).
;   flat_selfref - self-referential loop PHI (doubling), captured on exit edge.
;   flat_swap    - two mutually-dependent loop PHIs (swap); exercises the
;                  phi-in-successor termination path of translate_value_for_edge.
; flat_* are flattened, ref_* are baselines; main returns nonzero on mismatch.

; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=1 -passes='obf-control-flatten,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/control-flatten-ssa.yaml --obf-seed=9 -passes='obf-control-flatten,verify' -S %s -o %t9.ll
; RUN: %lli %t9.ll

; CHECK: obf.flat.dispatch:

define i32 @flat_indacc(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %loop ]
  %i.next = add i32 %i, 1
  %acc.next = add i32 %acc, %i.next
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %res = phi i32 [ %acc.next, %loop ]
  ret i32 %res
}

define i32 @ref_indacc(i32 %n) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %i.next, %loop ]
  %acc = phi i32 [ 0, %entry ], [ %acc.next, %loop ]
  %i.next = add i32 %i, 1
  %acc.next = add i32 %acc, %i.next
  %done = icmp sge i32 %i.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %res = phi i32 [ %acc.next, %loop ]
  ret i32 %res
}

define i32 @flat_selfref(i32 %n) {
entry:
  br label %loop
loop:
  %x = phi i32 [ 1, %entry ], [ %x.next, %loop ]
  %k = phi i32 [ 0, %entry ], [ %k.next, %loop ]
  %x.next = add i32 %x, %x
  %k.next = add i32 %k, 1
  %done = icmp sge i32 %k.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %res = phi i32 [ %x.next, %loop ]
  ret i32 %res
}

define i32 @ref_selfref(i32 %n) {
entry:
  br label %loop
loop:
  %x = phi i32 [ 1, %entry ], [ %x.next, %loop ]
  %k = phi i32 [ 0, %entry ], [ %k.next, %loop ]
  %x.next = add i32 %x, %x
  %k.next = add i32 %k, 1
  %done = icmp sge i32 %k.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %res = phi i32 [ %x.next, %loop ]
  ret i32 %res
}

define i32 @flat_swap(i32 %n) {
entry:
  br label %loop
loop:
  %a = phi i32 [ 1, %entry ], [ %b, %loop ]
  %b = phi i32 [ 2, %entry ], [ %a, %loop ]
  %k = phi i32 [ 0, %entry ], [ %k.next, %loop ]
  %k.next = add i32 %k, 1
  %done = icmp sge i32 %k.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %resa = phi i32 [ %a, %loop ]
  %resb = phi i32 [ %b, %loop ]
  %res = add i32 %resa, %resb
  ret i32 %res
}

define i32 @ref_swap(i32 %n) {
entry:
  br label %loop
loop:
  %a = phi i32 [ 1, %entry ], [ %b, %loop ]
  %b = phi i32 [ 2, %entry ], [ %a, %loop ]
  %k = phi i32 [ 0, %entry ], [ %k.next, %loop ]
  %k.next = add i32 %k, 1
  %done = icmp sge i32 %k.next, %n
  br i1 %done, label %exit, label %loop
exit:
  %resa = phi i32 [ %a, %loop ]
  %resb = phi i32 [ %b, %loop ]
  %res = add i32 %resa, %resb
  ret i32 %res
}

define i32 @main() {
entry:
  br label %loop
loop:
  %n = phi i32 [ 1, %entry ], [ %n.next, %loop ]
  %bad = phi i32 [ 0, %entry ], [ %bad.next, %loop ]
  %fa = call i32 @flat_indacc(i32 %n)
  %ra = call i32 @ref_indacc(i32 %n)
  %da = icmp ne i32 %fa, %ra
  %fb = call i32 @flat_selfref(i32 %n)
  %rb = call i32 @ref_selfref(i32 %n)
  %db = icmp ne i32 %fb, %rb
  %fc = call i32 @flat_swap(i32 %n)
  %rc = call i32 @ref_swap(i32 %n)
  %dc = icmp ne i32 %fc, %rc
  %or1 = or i1 %da, %db
  %or2 = or i1 %or1, %dc
  %z = zext i1 %or2 to i32
  %bad.next = add i32 %bad, %z
  %n.next = add i32 %n, 1
  %done = icmp eq i32 %n.next, 12
  br i1 %done, label %exit, label %loop
exit:
  ret i32 %bad.next
}
