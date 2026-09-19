; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for entry block branch target rejection in indirect dispatch:
; In LLVM, the function entry block cannot have predecessors and cannot have BlockAddress taken.
; If a conditional branch or switch has the entry block as a target, indirect dispatch must
; reject that site rather than emitting an invalid indirectbr to the entry block.
; CHECK-LABEL: define i32 @entry_loop_target
; CHECK-NOT: blockaddress(@entry_loop_target, %entry)
define i32 @entry_loop_target(i32 %x) {
entry:
  %cmp = icmp slt i32 %x, 10
  br i1 %cmp, label %loop, label %exit

loop:
  %i = phi i32 [ %x, %entry ], [ %next, %loop ]
  %next = add i32 %i, 1
  %done = icmp sge i32 %next, 10
  br i1 %done, label %exit, label %loop

exit:
  %ret = phi i32 [ 0, %entry ], [ %i, %loop ]
  ret i32 %ret
}

define i32 @main() {
entry:
  %res = call i32 @entry_loop_target(i32 1)
  %ok = icmp eq i32 %res, 9
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
