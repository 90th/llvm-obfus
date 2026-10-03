; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status, (.count | tostring), .detail] | join("|")' | %FileCheck %s --check-prefix=ADMIT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-budget.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status, (.count | tostring), .detail] | join("|")' | %FileCheck %s --check-prefix=BUDGET
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema.yaml -passes='obf-vm,verify' -S %s -o %t.ll
; RUN: %FileCheck %s --check-prefix=PROTECTED < %t.ll
; RUN: %lli %s
; RUN: %lli %t.ll

; Each scalar call lowers to two freezes + compare + select + ret (5 virtual instructions).
; A vector max must still be rejected rather than sent to scalar handlers.
declare i8 @llvm.smax.i8(i8, i8)
declare i8 @llvm.umax.i8(i8, i8)
declare i64 @llvm.smax.i64(i64, i64)
declare i64 @llvm.umax.i64(i64, i64)
declare i32 @llvm.smin.i32(i32, i32)
declare i32 @llvm.umin.i32(i32, i32)
declare <2 x i8> @llvm.smax.v2i8(<2 x i8>, <2 x i8>)

define i8 @vm_smax8(i8 %lhs, i8 %rhs) {
entry:
  %result = call i8 @llvm.smax.i8(i8 %lhs, i8 %rhs)
  ret i8 %result
}

define i8 @vm_umax8(i8 %lhs, i8 %rhs) {
entry:
  %result = call i8 @llvm.umax.i8(i8 %lhs, i8 %rhs)
  ret i8 %result
}

define i64 @vm_smax64(i64 %lhs, i64 %rhs) {
entry:
  %result = call i64 @llvm.smax.i64(i64 %lhs, i64 %rhs)
  ret i64 %result
}

define i64 @vm_umax64(i64 %lhs, i64 %rhs) {
entry:
  %result = call i64 @llvm.umax.i64(i64 %lhs, i64 %rhs)
  ret i64 %result
}

define i32 @vm_smin32(i32 %lhs, i32 %rhs) {
entry:
  %result = call i32 @llvm.smin.i32(i32 %lhs, i32 %rhs)
  ret i32 %result
}

define i32 @vm_umin32(i32 %lhs, i32 %rhs) {
entry:
  %result = call i32 @llvm.umin.i32(i32 %lhs, i32 %rhs)
  ret i32 %result
}

define <2 x i8> @vm_vector_max(<2 x i8> %lhs, <2 x i8> %rhs) {
entry:
  %result = call <2 x i8> @llvm.smax.v2i8(<2 x i8> %lhs, <2 x i8> %rhs)
  ret <2 x i8> %result
}

define i32 @main() {
entry:
  %s8.a = call i8 @vm_smax8(i8 -128, i8 127)
  %s8.b = call i8 @vm_smax8(i8 127, i8 -128)
  %s8.tie = call i8 @vm_smax8(i8 -1, i8 -1)
  %u8.a = call i8 @vm_umax8(i8 -1, i8 1)
  %u8.b = call i8 @vm_umax8(i8 1, i8 -1)
  %u8.tie = call i8 @vm_umax8(i8 7, i8 7)
  %s64.a = call i64 @vm_smax64(i64 -9223372036854775808, i64 9223372036854775807)
  %s64.b = call i64 @vm_smax64(i64 9223372036854775807, i64 -9223372036854775808)
  %s64.tie = call i64 @vm_smax64(i64 -4, i64 -4)
  %u64.a = call i64 @vm_umax64(i64 -1, i64 1)
  %u64.b = call i64 @vm_umax64(i64 1, i64 -1)
  %u64.tie = call i64 @vm_umax64(i64 42, i64 42)
  %smin = call i32 @vm_smin32(i32 -8, i32 3)
  %umin = call i32 @vm_umin32(i32 -1, i32 1)
  %vmax = call <2 x i8> @vm_vector_max(<2 x i8> <i8 -8, i8 3>, <2 x i8> <i8 2, i8 -4>)
  %v0 = extractelement <2 x i8> %vmax, i32 0
  %v1 = extractelement <2 x i8> %vmax, i32 1
  %bad0 = icmp ne i8 %s8.a, 127
  %bad1 = icmp ne i8 %s8.b, 127
  %bad2 = icmp ne i8 %s8.tie, -1
  %bad3 = icmp ne i8 %u8.a, -1
  %bad4 = icmp ne i8 %u8.b, -1
  %bad5 = icmp ne i8 %u8.tie, 7
  %bad6 = icmp ne i64 %s64.a, 9223372036854775807
  %bad7 = icmp ne i64 %s64.b, 9223372036854775807
  %bad8 = icmp ne i64 %s64.tie, -4
  %bad9 = icmp ne i64 %u64.a, -1
  %bad10 = icmp ne i64 %u64.b, -1
  %bad11 = icmp ne i64 %u64.tie, 42
  %bad12 = icmp ne i32 %smin, -8
  %bad13 = icmp ne i32 %umin, 1
  %bad14 = icmp ne i8 %v0, 2
  %bad15 = icmp ne i8 %v1, 3
  %errors0 = or i1 %bad0, %bad1
  %errors1 = or i1 %errors0, %bad2
  %errors2 = or i1 %errors1, %bad3
  %errors3 = or i1 %errors2, %bad4
  %errors4 = or i1 %errors3, %bad5
  %errors5 = or i1 %errors4, %bad6
  %errors6 = or i1 %errors5, %bad7
  %errors7 = or i1 %errors6, %bad8
  %errors8 = or i1 %errors7, %bad9
  %errors9 = or i1 %errors8, %bad10
  %errors10 = or i1 %errors9, %bad11
  %errors11 = or i1 %errors10, %bad12
  %errors12 = or i1 %errors11, %bad13
  %errors13 = or i1 %errors12, %bad14
  %errors14 = or i1 %errors13, %bad15
  %code = zext i1 %errors14 to i32
  ret i32 %code
}

; ADMIT-DAG: vm_smax8|candidate|5|
; ADMIT-DAG: vm_umax8|candidate|5|
; ADMIT-DAG: vm_smax64|candidate|5|
; ADMIT-DAG: vm_umax64|candidate|5|
; ADMIT-DAG: vm_smin32|candidate|5|
; ADMIT-DAG: vm_umin32|candidate|5|
; ADMIT-DAG: vm_vector_max|not_candidate|0|unsupported intrinsic: llvm.smax.v2i8
; BUDGET-DAG: vm_smax8|not_candidate|0|too many virtual instructions (5 > 4)
; BUDGET-DAG: vm_umax64|not_candidate|0|too many virtual instructions (5 > 4)

; PROTECTED-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}} = private unnamed_addr constant
; PROTECTED-LABEL: define i8 @vm_smax8(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i8 %vm_smax8.obf.wrapper.indirect
; PROTECTED-NOT: call i8 @llvm.smax.i8
; PROTECTED-LABEL: define i8 @vm_umax8(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i8 %vm_umax8.obf.wrapper.indirect
; PROTECTED-NOT: call i8 @llvm.umax.i8
; PROTECTED-LABEL: define i64 @vm_smax64(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i64 %vm_smax64.obf.wrapper.indirect
; PROTECTED-NOT: call i64 @llvm.smax.i64
; PROTECTED-LABEL: define i64 @vm_umax64(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i64 %vm_umax64.obf.wrapper.indirect
; PROTECTED-NOT: call i64 @llvm.umax.i64
; PROTECTED-LABEL: define i32 @vm_smin32(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i32 %vm_smin32.obf.wrapper.indirect
; PROTECTED-LABEL: define i32 @vm_umin32(
; PROTECTED: entry.obf.vm.wrapper:
; PROTECTED: call i32 %vm_umin32.obf.wrapper.indirect
; PROTECTED-LABEL: define <2 x i8> @vm_vector_max(
; PROTECTED: call <2 x i8> @llvm.smax.v2i8
