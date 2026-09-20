; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes=obf-zero-comparison -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll
; RUN: %lli %t.ll

; Regression fixture for zero-comparison string & memory lowering:
; 1. Signed strcmp (< 0) must NOT be replaced with unsigned delta (semantics preserved).
; 2. Equality strcmp (== 0) MUST be lowered to zero-reduction.
; 3. Signed memcmp (< 0) must NOT be replaced with unsigned delta.
; 4. Equality memcmp (== 0) with length > 0 MUST be lowered to zero-reduction.
; 5. Zero-length memcmp (len = 0) must NOT be unrolled.

@.str.apple = private unnamed_addr constant [6 x i8] c"apple\00", align 1
@.str.banana = private unnamed_addr constant [7 x i8] c"banana\00", align 1

declare i32 @strcmp(ptr, ptr)
declare i32 @memcmp(ptr, ptr, i64)

; CHECK-LABEL: define i32 @test_strcmp_signed
; CHECK: call i32 @strcmp
define i32 @test_strcmp_signed(ptr %s1, ptr %s2) {
entry:
  %res = call i32 @strcmp(ptr @.str.apple, ptr %s2)
  %cmp = icmp slt i32 %res, 0
  %val = select i1 %cmp, i32 1, i32 2
  ret i32 %val
}

; CHECK-LABEL: define i32 @test_strcmp_equality
; CHECK-NOT: call i32 @strcmp
; CHECK: obf.zero.str.delta
define i32 @test_strcmp_equality(ptr %s1) {
entry:
  %res = call i32 @strcmp(ptr %s1, ptr @.str.apple)
  %cmp = icmp eq i32 %res, 0
  %val = select i1 %cmp, i32 10, i32 20
  ret i32 %val
}

; CHECK-LABEL: define i32 @test_memcmp_signed
; CHECK: call i32 @memcmp
define i32 @test_memcmp_signed(ptr %s1, ptr %s2) {
entry:
  %res = call i32 @memcmp(ptr %s1, ptr %s2, i64 4)
  %cmp = icmp slt i32 %res, 0
  %val = select i1 %cmp, i32 100, i32 200
  ret i32 %val
}

; CHECK-LABEL: define i32 @test_memcmp_equality
; CHECK-NOT: call i32 @memcmp
; CHECK: obf.zero.str.delta
define i32 @test_memcmp_equality(ptr %s1, ptr %s2) {
entry:
  %res = call i32 @memcmp(ptr %s1, ptr %s2, i64 4)
  %cmp = icmp eq i32 %res, 0
  %val = select i1 %cmp, i32 1000, i32 2000
  ret i32 %val
}

; CHECK-LABEL: define i32 @test_memcmp_zero_len
; CHECK: call i32 @memcmp
define i32 @test_memcmp_zero_len(ptr %s1, ptr %s2) {
entry:
  %res = call i32 @memcmp(ptr %s1, ptr %s2, i64 0)
  %cmp = icmp eq i32 %res, 0
  %val = select i1 %cmp, i32 1, i32 0
  ret i32 %val
}

define i32 @main() {
entry:
  ; "apple" < "banana" -> strcmp signed returns 1
  %c1 = call i32 @test_strcmp_signed(ptr @.str.apple, ptr @.str.banana)
  %ok1 = icmp eq i32 %c1, 1
  br i1 %ok1, label %check2, label %fail

check2:
  ; "apple" == "apple" -> strcmp eq returns 10
  %c2 = call i32 @test_strcmp_equality(ptr @.str.apple)
  %ok2 = icmp eq i32 %c2, 10
  br i1 %ok2, label %check3, label %fail

check3:
  ; "apple" < "banana" -> memcmp signed returns 100
  %c3 = call i32 @test_memcmp_signed(ptr @.str.apple, ptr @.str.banana)
  %ok3 = icmp eq i32 %c3, 100
  br i1 %ok3, label %check4, label %fail

check4:
  ; "appl" == "appl" -> memcmp eq returns 1000
  %c4 = call i32 @test_memcmp_equality(ptr @.str.apple, ptr @.str.apple)
  %ok4 = icmp eq i32 %c4, 1000
  br i1 %ok4, label %check5, label %fail

check5:
  ; zero-length memcmp
  %c5 = call i32 @test_memcmp_zero_len(ptr @.str.apple, ptr @.str.banana)
  %ok5 = icmp eq i32 %c5, 1
  br i1 %ok5, label %pass, label %fail

pass:
  ret i32 0

fail:
  ret i32 1
}
