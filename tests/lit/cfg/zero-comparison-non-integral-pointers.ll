; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes=obf-zero-comparison -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %opt -passes=verify -disable-output %t.ll

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128-ni:1:2"

; Ordinary pointer icmp eq (addrspace 0, integral): MUST be lowered to zero-reduction using ptrtoint.
; CHECK-LABEL: define i1 @test_ordinary_ptr_eq
; CHECK-DAG: %{{.*}} = ptrtoint ptr %p to i64
; CHECK-DAG: %{{.*}} = ptrtoint ptr %q to i64
; CHECK: obf.zero.delta
; CHECK: ret i1
define i1 @test_ordinary_ptr_eq(ptr %p, ptr %q) {
  %cmp = icmp eq ptr %p, %q
  ret i1 %cmp
}

; Ordinary pointer icmp ne (addrspace 0, integral): MUST be lowered to zero-reduction using ptrtoint.
; CHECK-LABEL: define i1 @test_ordinary_ptr_ne
; CHECK-DAG: %{{.*}} = ptrtoint ptr %p to i64
; CHECK-DAG: %{{.*}} = ptrtoint ptr %q to i64
; CHECK: obf.zero.delta
; CHECK: ret i1
define i1 @test_ordinary_ptr_ne(ptr %p, ptr %q) {
  %cmp = icmp ne ptr %p, %q
  ret i1 %cmp
}

; Non-integral pointer icmp eq (addrspace 1, non-integral via ni:1:2):
; MUST NOT synthesize ptrtoint and MUST be preserved untouched.
; CHECK-LABEL: define i1 @test_non_integral_ptr_eq
; CHECK-NOT: ptrtoint
; CHECK-NOT: obf.zero
; CHECK: %cmp = icmp eq ptr addrspace(1) %p, %q
; CHECK-NEXT: ret i1 %cmp
define i1 @test_non_integral_ptr_eq(ptr addrspace(1) %p, ptr addrspace(1) %q) {
  %cmp = icmp eq ptr addrspace(1) %p, %q
  ret i1 %cmp
}

; Non-integral pointer icmp ne (addrspace 2, non-integral via ni:1:2):
; MUST NOT synthesize ptrtoint and MUST be preserved untouched.
; CHECK-LABEL: define i1 @test_non_integral_ptr_ne
; CHECK-NOT: ptrtoint
; CHECK-NOT: obf.zero
; CHECK: %cmp = icmp ne ptr addrspace(2) %p, %q
; CHECK-NEXT: ret i1 %cmp
define i1 @test_non_integral_ptr_ne(ptr addrspace(2) %p, ptr addrspace(2) %q) {
  %cmp = icmp ne ptr addrspace(2) %p, %q
  ret i1 %cmp
}

; Select using non-integral pointer comparison condition:
; Condition MUST NOT be lowered by zero_comparison.
; CHECK-LABEL: define i32 @test_non_integral_select
; CHECK-NOT: ptrtoint
; CHECK-NOT: obf.zero
; CHECK: %cmp = icmp eq ptr addrspace(1) %p, %q
; CHECK-NEXT: %sel = select i1 %cmp, i32 %a, i32 %b
; CHECK-NEXT: ret i32 %sel
define i32 @test_non_integral_select(ptr addrspace(1) %p, ptr addrspace(1) %q, i32 %a, i32 %b) {
  %cmp = icmp eq ptr addrspace(1) %p, %q
  %sel = select i1 %cmp, i32 %a, i32 %b
  ret i32 %sel
}
