; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"

@.str.apple = private unnamed_addr constant [6 x i8] c"apple\00", align 1

; Canonical libc declarations
declare i32 @strcmp(ptr, ptr)
declare i32 @strncmp(ptr, ptr, i64)
declare i32 @memcmp(ptr, ptr, i64)
declare i32 @bcmp(ptr, ptr, i64)

; -----------------------------------------------------------------------------
; Positive test cases: standard libc calls MUST be transformed
; -----------------------------------------------------------------------------

; CHECK-LABEL: define i1 @test_positive_strcmp
; CHECK-NOT: call i32 @strcmp
; CHECK: obf.zero.str.delta
; CHECK: ret i1
define i1 @test_positive_strcmp(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; CHECK-LABEL: define i1 @test_positive_strncmp
; CHECK-NOT: call i32 @strncmp
; CHECK: obf.zero.str.delta
; CHECK: ret i1
define i1 @test_positive_strncmp(ptr %s) {
entry:
  %r = call i32 @strncmp(ptr %s, ptr @.str.apple, i64 4)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; CHECK-LABEL: define i1 @test_positive_memcmp
; CHECK-NOT: call i32 @memcmp
; CHECK: obf.zero.str.xor
; CHECK: ret i1
define i1 @test_positive_memcmp(ptr %s) {
entry:
  %r = call i32 @memcmp(ptr %s, ptr @.str.apple, i64 4)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; CHECK-LABEL: define i1 @test_positive_bcmp
; CHECK-NOT: call i32 @bcmp
; CHECK: obf.zero.str.xor
; CHECK: ret i1
define i1 @test_positive_bcmp(ptr %s) {
entry:
  %r = call i32 @bcmp(ptr %s, ptr @.str.apple, i64 4)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; -----------------------------------------------------------------------------
; Negative test cases on canonical declarations: MUST remain intact
; -----------------------------------------------------------------------------

; 1. Call-site nobuiltin attribute
; CHECK-LABEL: define i1 @test_negative_callsite_nobuiltin
; CHECK: %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_nobuiltin(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple) #0
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 2. Call-site per-name string attribute ("no-builtin-strcmp")
; CHECK-LABEL: define i1 @test_negative_callsite_per_name_nobuiltin
; CHECK: %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_per_name_nobuiltin(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple) #1
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 3. Caller function with "no-builtins" attribute
; CHECK-LABEL: define i1 @test_negative_caller_no_builtins
; CHECK: %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_caller_no_builtins(ptr %s) #2 {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 4. Caller function with nobuiltin enum attribute
; CHECK-LABEL: define i1 @test_negative_caller_nobuiltin_enum
; CHECK: %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_caller_nobuiltin_enum(ptr %s) #0 {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 5. Non-C calling convention on call site
; CHECK-LABEL: define i1 @test_negative_callsite_fastcc
; CHECK: %r = call fastcc i32 @strcmp(ptr %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_fastcc(ptr %s) {
entry:
  %r = call fastcc i32 @strcmp(ptr %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 6. Incompatible operand bundle
; CHECK-LABEL: define i1 @test_negative_operand_bundle
; CHECK: %r = call i32 @strcmp(ptr %s, ptr @.str.apple) [ "deopt"() ]
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_operand_bundle(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr %s, ptr @.str.apple) [ "deopt"() ]
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 7. Musttail call on otherwise-eligible bcmp with constant string & length
; CHECK-LABEL: define i32 @test_negative_musttail_bcmp
; CHECK: %r = musttail call i32 @bcmp(ptr %s, ptr @.str.apple, i64 4)
; CHECK: ret i32 %r
define i32 @test_negative_musttail_bcmp(ptr %s, ptr %s2, i64 %len) {
entry:
  %r = musttail call i32 @bcmp(ptr %s, ptr @.str.apple, i64 4)
  ret i32 %r
}

; 8. Incompatible pointer parameter attribute (byval) on call site
; CHECK-LABEL: define i1 @test_negative_callsite_byval
; CHECK: %r = call i32 @strcmp(ptr byval(i8) %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_byval(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr byval(i8) %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 9. Incompatible pointer parameter attribute (byref) on call site
; CHECK-LABEL: define i1 @test_negative_callsite_byref
; CHECK: %r = call i32 @strcmp(ptr byref(i8) %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_byref(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr byref(i8) %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; 10. Incompatible pointer parameter attribute (inreg) on call site
; CHECK-LABEL: define i1 @test_negative_callsite_inreg
; CHECK: %r = call i32 @strcmp(ptr inreg %s, ptr @.str.apple)
; CHECK-NOT: obf.zero.str
; CHECK: ret i1
define i1 @test_negative_callsite_inreg(ptr %s) {
entry:
  %r = call i32 @strcmp(ptr inreg %s, ptr @.str.apple)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

attributes #0 = { nobuiltin }
attributes #1 = { "no-builtin-strcmp" }
attributes #2 = { "no-builtins" }
