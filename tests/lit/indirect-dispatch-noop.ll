; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch.yaml -passes=obf-indirect-dispatch -disable-output %s

declare i32 @__CxxFrameHandler3(...)
declare void @may_throw_void()

define void @has_invoke_and_catchswitch() personality ptr @__CxxFrameHandler3 {
entry:
  invoke void @may_throw_void()
          to label %exit unwind label %catch.dispatch

catch.dispatch:
  %cs = catchswitch within none [label %catch] unwind to caller

catch:
  %cp = catchpad within %cs [ptr null, i32 64, ptr null]
  catchret from %cp to label %exit

exit:
  ret void
}

define i32 @has_indirectbr(i1 %cond) {
entry:
  %addr = select i1 %cond, ptr blockaddress(@has_indirectbr, %left), ptr blockaddress(@has_indirectbr, %right)
  indirectbr ptr %addr, [label %left, label %right]

left:
  ret i32 1

right:
  ret i32 2
}

; CHECK-LABEL: define void @has_invoke_and_catchswitch()
; CHECK: invoke void @may_throw_void()
; CHECK: catchswitch within none [label %catch] unwind to caller
; CHECK: %cp = catchpad within %cs [ptr null, i32 64, ptr null]
; CHECK: catchret from %cp to label %exit
; CHECK-LABEL: define i32 @has_indirectbr(i1 %cond)
; CHECK: %addr = select i1 %cond, ptr blockaddress(@has_indirectbr, %left), ptr blockaddress(@has_indirectbr, %right)
; CHECK: indirectbr ptr %addr, [label %left, label %right]
; CHECK-NOT: freeze
