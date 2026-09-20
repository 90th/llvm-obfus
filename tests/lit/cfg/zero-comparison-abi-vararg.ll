; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"

@.str.apple = private unnamed_addr constant [6 x i8] c"apple\00", align 1

declare i32 @strcmp(ptr, ptr, ...)

; CHECK-LABEL: define i1 @test_vararg
; CHECK: %r = call i32 (ptr, ptr, ...) @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str.delta
; CHECK: ret i1
define i1 @test_vararg(ptr %s) {
entry:
  %r = call i32 (ptr, ptr, ...) @strcmp(ptr %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}
