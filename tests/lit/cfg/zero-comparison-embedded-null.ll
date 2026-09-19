; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes=obf-zero-comparison -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for embedded null bytes in string comparisons:
; @s1 and @s2 share prefix "foo\0" but differ after the first null byte.
; In C, strcmp(@s1, @s2) must compare equal (0) because the string ends at the first null.
; Any transform must preserve strcmp(@s1, @s2) == 0.

@s1 = private unnamed_addr constant [8 x i8] c"foo\00bar\00", align 1
@s2 = private unnamed_addr constant [8 x i8] c"foo\00baz\00", align 1

declare i32 @strcmp(ptr, ptr)

; CHECK-LABEL: define i32 @test_embedded_null_cmp
define i32 @test_embedded_null_cmp() {
entry:
  %res = call i32 @strcmp(ptr @s1, ptr @s2)
  %cmp = icmp eq i32 %res, 0
  %val = select i1 %cmp, i32 0, i32 1
  ret i32 %val
}

define i32 @main() {
entry:
  %rc = call i32 @test_embedded_null_cmp()
  ret i32 %rc
}
