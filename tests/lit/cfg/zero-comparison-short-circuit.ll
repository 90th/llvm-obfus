; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %lli %t.ll
; RUN: %opt -passes='default<O2>,verify' -S %t.ll -o %t.opt.ll
; RUN: %lli %t.opt.ll

target triple = "x86_64-unknown-linux-gnu"

@a_x = private constant [4 x i8] c"a\00X\00"
@a_y = private constant [4 x i8] c"a\00Y\00"
@b_x = private constant [4 x i8] c"b\00X\00"
@abc = private constant [4 x i8] c"abc\00"
@abd = private constant [4 x i8] c"abd\00"
@apple = private constant [6 x i8] c"apple\00"
@short = private constant [2 x i8] c"x\00"
@empty = private constant [1 x i8] zeroinitializer
@mutable = global [6 x i8] c"a\00xxx\00"

declare i32 @strcmp(ptr, ptr)
declare i32 @strncmp(ptr, ptr, i64)
declare i32 @memcmp(ptr, ptr, i64)
declare i32 @bcmp(ptr, ptr, i64)

; CHECK-LABEL: define i1 @bounded
; CHECK-NOT: call i32 @strncmp
; CHECK: ret i1
; Both equality consumers must observe the same short-circuit result.
define i1 @bounded(ptr %left, ptr %right) {
entry:
  %r = call i32 @strncmp(ptr %left, ptr %right, i64 3)
  %eq = icmp eq i32 %r, 0
  %ne = icmp ne i32 0, %r
  %not_ne = xor i1 %ne, true
  %both = and i1 %eq, %not_ne
  ret i1 %both
}

; CHECK-LABEL: define i1 @zero_length
; CHECK-NOT: load
; CHECK: ret i1
define i1 @zero_length(ptr %left, ptr %right) {
entry:
  %r = call i32 @strncmp(ptr %left, ptr %right, i64 0)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

; CHECK-LABEL: define i1 @unbounded
; CHECK-NOT: call i32 @strcmp
; CHECK: ret i1
define i1 @unbounded(ptr %left) {
entry:
  %r = call i32 @strcmp(ptr %left, ptr @apple)
  %eq = icmp eq i32 %r, 0
  br label %exit
exit:
  %result = phi i1 [ %eq, %entry ]
  ret i1 %result
}

; CHECK-LABEL: define i1 @memory
; CHECK-NOT: call i32 @memcmp
; CHECK-NOT: call i32 @bcmp
; CHECK: ret i1
define i1 @memory(ptr %left, ptr %right) {
entry:
  %m = call i32 @memcmp(ptr %left, ptr %right, i64 3)
  %b = call i32 @bcmp(ptr %left, ptr %right, i64 3)
  %mn = icmp ne i32 %m, 0
  %bn = icmp ne i32 %b, 0
  %both = and i1 %mn, %bn
  ret i1 %both
}

; A mutable initializer does not bound the length at the call.
; CHECK-LABEL: define i1 @mutable_string
; CHECK: call i32 @strcmp
define i1 @mutable_string(ptr %other) {
entry:
  %r = call i32 @strcmp(ptr @mutable, ptr %other)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

define i32 @main() {
entry:
  %embedded = call i1 @bounded(ptr @a_x, ptr @a_y)
  %equal = call i1 @bounded(ptr @abc, ptr @abc)
  %mismatch = call i1 @bounded(ptr @a_x, ptr @b_x)
  %before_nul = call i1 @bounded(ptr @abc, ptr @abd)
  %zero = call i1 @zero_length(ptr @a_x, ptr @b_x)
  %shorter = call i1 @unbounded(ptr @short)
  %empty_result = call i1 @unbounded(ptr @empty)
  %same = call i1 @unbounded(ptr @apple)
  %fixed_length = call i1 @memory(ptr @a_x, ptr @a_y)
  store i8 98, ptr getelementptr ([6 x i8], ptr @mutable, i64 0, i64 1)
  store i8 100, ptr getelementptr ([6 x i8], ptr @mutable, i64 0, i64 2)
  store i8 0, ptr getelementptr ([6 x i8], ptr @mutable, i64 0, i64 3)
  %changed = call i1 @mutable_string(ptr @abc)
  %good1 = and i1 %embedded, %equal
  %good2 = and i1 %zero, %same
  %good3 = and i1 %good1, %good2
  %good4 = and i1 %good3, %fixed_length
  %bad1 = or i1 %mismatch, %before_nul
  %bad2 = or i1 %shorter, %empty_result
  %bad3 = or i1 %bad1, %bad2
  %bad4 = or i1 %bad3, %changed
  %no_bad = xor i1 %bad4, true
  %ok = and i1 %good4, %no_bad
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}
