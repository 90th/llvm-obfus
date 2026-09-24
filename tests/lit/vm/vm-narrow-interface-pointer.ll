; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-linkage-attrs.yaml -passes=obf-vm,verify -S %s -o - | %FileCheck %s

target datalayout = "e-m:e-p:64:64-p1:32:32-i64:64-n8:16:32:64-S128"

define i32 @attr_readonly(i32 %x) addrspace(1) {
entry:
  %sum = add i32 %x, 7
  ret i32 %sum
}

define i32 @caller() {
entry:
  %result = call addrspace(1) i32 @attr_readonly(i32 5)
  ret i32 %result
}

; CHECK-LABEL: define i32 @attr_readonly(i32 %x) addrspace(1)
; CHECK: %attr_readonly.obf.wrapper.target.seed.value = call i32 @__obf_vm_seed_resolve.i32(i32
; CHECK: %attr_readonly.obf.wrapper.indirect = inttoptr i32 {{.*}} to ptr addrspace(1)
; CHECK: call addrspace(1) i32 %attr_readonly.obf.wrapper.indirect(i32 %x, i64
; CHECK-LABEL: define i32 @caller()
; CHECK: %attr_readonly.obf.indirect = inttoptr i32 {{.*}} to ptr addrspace(1)
; CHECK: call addrspace(1) i32 %attr_readonly.obf.indirect(i32 5, i64
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token) addrspace(1)
; CHECK: ptrtoint (ptr addrspace(1) blockaddress(
