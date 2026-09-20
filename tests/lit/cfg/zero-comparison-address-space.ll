; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/zero-comparison.yaml -passes='obf-zero-comparison,verify' -S %s -o %t.ll
; RUN: %FileCheck %s < %t.ll
; RUN: %lli %t.ll

target datalayout = "e-p:64:64-p1:64:64-p2:64:64-i64:64-n8:16:32:64-S128"
@left = private addrspace(1) constant [4 x i8] c"a\00X\00"
@right = private addrspace(2) constant [4 x i8] c"a\00Y\00"
declare i32 @strncmp(ptr addrspace(1), ptr addrspace(2), i64)

; CHECK-LABEL: define i1 @compare_spaces
; CHECK-NOT: addrspacecast
; CHECK: load i8, ptr addrspace(1)
; CHECK: load i8, ptr addrspace(2)
; CHECK-NOT: call i32 @strncmp
; CHECK: ret i1
define i1 @compare_spaces(ptr addrspace(1) %lhs, ptr addrspace(2) %rhs) {
entry:
  %r = call i32 @strncmp(ptr addrspace(1) %lhs, ptr addrspace(2) %rhs, i64 3)
  %eq = icmp eq i32 %r, 0
  ret i1 %eq
}

define i32 @main() {
entry:
  %eq = call i1 @compare_spaces(ptr addrspace(1) @left, ptr addrspace(2) @right)
  %status = select i1 %eq, i32 0, i32 1
  ret i32 %status
}
