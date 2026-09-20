; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for a legal loop backedge: the entry-target guard must not
; reject a conditional branch whose successors are %exit and %loop, and the
; rewritten site must still materialize an indirectbr.
; CHECK-LABEL: define i32 @loop_backedge_dispatch
; CHECK-DAG: ptrtoint (ptr blockaddress(@loop_backedge_dispatch, %exit) to i64)
; CHECK-DAG: ptrtoint (ptr blockaddress(@loop_backedge_dispatch, %loop) to i64)
; CHECK: %obf.idis.cond = freeze i1 %done
; CHECK: indirectbr ptr %obf.idis.dest, [label %exit, label %loop]
; CHECK-NOT: br i1 %done
; CHECK-NOT: blockaddress(@loop_backedge_dispatch, %entry)
define i32 @loop_backedge_dispatch(i32 %x) {
entry:
  br label %loop

loop:
  %i = phi i32 [ %x, %entry ], [ %next, %loop ]
  %next = add i32 %i, 1
  %done = icmp sge i32 %next, 10
  br i1 %done, label %exit, label %loop

exit:
  ret i32 %i
}

define i32 @main() {
entry:
  %res = call i32 @loop_backedge_dispatch(i32 1)
  %ok = icmp eq i32 %res, 9
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
