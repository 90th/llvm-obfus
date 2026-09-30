; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-linkage-attrs.yaml -passes=obf-vm,verify -S %s -o - | %FileCheck %s

target datalayout = "e-m:e-p:64:64-p1:32:32-i64:64-n8:16:32:64-S128"

define i32 @attr_readnone(i32 %x) {
entry:
  %sum = add i32 %x, 1
  ret i32 %sum
}

define i32 @attr_readonly(i32 %x) addrspace(1) {
entry:
  %sum = add i32 %x, 2
  ret i32 %sum
}

; CHECK-DAG: @[[TARGET64:__obf_vm_t_[A-Za-z0-9_]+]] = private global i64 {{-?[0-9]+}}, align 8
; CHECK-DAG: @[[TARGET32:__obf_vm_t_[A-Za-z0-9_]+]] = private global i32 {{-?[0-9]+}}, align 4

; CHECK-LABEL: define i32 @attr_readnone(
; CHECK: %attr_readnone.obf.wrapper.check = load atomic i64, ptr @[[TARGET64]] monotonic, align 8
; CHECK: call i64 @__obf_vm_seed_resolve(i64
; CHECK: store atomic i64 %attr_readnone.obf.wrapper.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET64]] monotonic, align 8
; CHECK-LABEL: define i32 @attr_readonly(
; CHECK: %attr_readonly.obf.wrapper.check = load atomic i32, ptr @[[TARGET32]] monotonic, align 4
; CHECK: call i32 @__obf_vm_seed_resolve.i32(i32
; CHECK: store atomic i32 %attr_readonly.obf.wrapper.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET32]] monotonic, align 4
; CHECK-DAG: define private i64 @__obf_vm_seed_resolve(i64
; CHECK-DAG: define private i32 @__obf_vm_seed_resolve.i32(i32
