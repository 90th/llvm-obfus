; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strategy-report.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s

@.compare = private unnamed_addr constant [8 x i8] c"delta-7\00"
@.shared = private unnamed_addr constant [7 x i8] c"shared\00"

declare i32 @bcmp(ptr, ptr, i64)

define ptr @leak_shared() {
entry:
  ret ptr @.shared
}

define i32 @main() {
entry:
  %cmp = call i32 @bcmp(ptr @.compare, ptr @.compare, i64 7)
  %shared = call i32 @bcmp(ptr @.shared, ptr @.shared, i64 6)
  %ok1 = icmp eq i32 %cmp, 0
  %ok2 = icmp eq i32 %shared, 0
  %ok = and i1 %ok1, %ok2
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: "inline_eligible":true{{.*}}"kind":"inline_stack_decode"{{.*}}"compare_call_operand"{{.*}}"target_name":".compare"
; CHECK: "detail":"lazy_decode: 3 lazy use(s)"{{.*}}"kind":"helper_lazy_decode"{{.*}}"compare_call_operand"{{.*}}"return_operand"{{.*}}"target_name":".shared"
