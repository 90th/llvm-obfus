; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-compare.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %FileCheck %s < %t

target datalayout = "e-p:64:64"

@.custom = private unnamed_addr constant [7 x i8] c"custom\00"
@.nobuiltin_call = private unnamed_addr constant [10 x i8] c"nobuiltin\00"
@.wrong_size_t = private unnamed_addr constant [6 x i8] c"width\00"

; Same symbol name, but this is a program-defined function rather than a libc
; declaration. Replacing it with lexical compare semantics would be incorrect.
define internal i32 @memcmp(ptr %lhs, ptr %rhs, i64 %n) {
entry:
  ret i32 123
}

declare i32 @strcmp(ptr, ptr)
declare i32 @strncmp(ptr, ptr, i32)

attributes #0 = { nobuiltin }

define i32 @check_custom_definition(ptr %rhs) {
entry:
  %r = call i32 @memcmp(ptr @.custom, ptr %rhs, i64 6)
  ret i32 %r
}

define i32 @check_nobuiltin_call(ptr %rhs) {
entry:
  %r = call i32 @strcmp(ptr @.nobuiltin_call, ptr %rhs) #0
  ret i32 %r
}

define i32 @check_wrong_size_t(ptr %rhs) {
entry:
  %r = call i32 @strncmp(ptr @.wrong_size_t, ptr %rhs, i32 5)
  ret i32 %r
}

; CHECK-LABEL: define i32 @check_custom_definition(
; CHECK-NOT: obf.str.cmp.
; CHECK: call i32 @memcmp(
; CHECK-LABEL: define i32 @check_nobuiltin_call(
; CHECK-NOT: obf.str.cmp.
; CHECK: call i32 @strcmp(
; CHECK-LABEL: define i32 @check_wrong_size_t(
; CHECK-NOT: obf.str.cmp.
; CHECK: call i32 @strncmp(
