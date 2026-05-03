; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-data-anchor-scattering.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-data-anchor-scattering.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @scatter_target(i32 %x, i32 %y) {
entry:
  %a0 = add i32 %x, 11
  %a1 = xor i32 %a0, %y
  %a2 = mul i32 %a1, 3
  %a3 = add i32 %a2, 19
  %a4 = sub i32 %a3, %x
  %a5 = xor i32 %a4, 305419896
  %a6 = add i32 %a5, %y
  %a7 = mul i32 %a6, 5
  %a8 = sub i32 %a7, 77
  %a9 = xor i32 %a8, %a3
  ret i32 %a9
}

define i32 @main() {
entry:
  %r = call i32 @scatter_target(i32 9, i32 4)
  %ok = icmp eq i32 %r, 1527099218
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @[[BC0:__obf_vm_bc_i_[A-Za-z0-9_]+]] = private unnamed_addr constant
; CHECK-DAG: @[[BC1:__obf_vm_bc_i_[A-Za-z0-9_]+_a[0-9A-Fa-f]+]] = private unnamed_addr constant
; CHECK-DAG: @[[PTR0:__obf_vm_ptrconst_[0-9A-F]+]] = private unnamed_addr constant ptr @[[BC0]]
; CHECK-DAG: @[[PTR1:__obf_vm_ptrconst_[0-9A-F]+]] = private unnamed_addr constant ptr @[[BC1]]

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; CHECK: %obf.vm.pred.slot = alloca i32
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; CHECK-DAG: "vm.bytecode.anchor.scattered"
; CHECK-DAG: "vm.bytecode.anchor.count.{{[2-9][0-9]*}}"
; CHECK-DAG: "vm.bytecode.anchor.real.{{[2-9][0-9]*}}"
