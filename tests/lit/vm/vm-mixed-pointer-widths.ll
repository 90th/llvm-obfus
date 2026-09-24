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

; CHECK-LABEL: define i32 @attr_readnone(
; CHECK: call i64 @__obf_vm_seed_resolve(i64
; CHECK-LABEL: define i32 @attr_readonly(
; CHECK: call i32 @__obf_vm_seed_resolve.i32(i32
; CHECK-DAG: define private i64 @__obf_vm_seed_resolve(i64
; CHECK-DAG: define private i32 @__obf_vm_seed_resolve.i32(i32
