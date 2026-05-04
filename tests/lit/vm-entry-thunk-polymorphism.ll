; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunk-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunk-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @poly_alpha(i32 %x) {
entry:
  %a = xor i32 %x, 17
  %b = add i32 %a, 5
  ret i32 %b
}

define i32 @poly_beta(i32 %x) {
entry:
  %a = mul i32 %x, 3
  %b = add i32 %a, 11
  ret i32 %b
}

define i32 @poly_gamma(i32 %x) {
entry:
  %a = sub i32 %x, 9
  %b = xor i32 %a, 34
  ret i32 %b
}

define i32 @poly_delta(i32 %x) {
entry:
  %a = shl i32 %x, 1
  %b = add i32 %a, 13
  ret i32 %b
}

define i32 @main() {
entry:
  %a = call i32 @poly_alpha(i32 10)
  %b = call i32 @poly_beta(i32 4)
  %c = call i32 @poly_gamma(i32 50)
  %d = call i32 @poly_delta(i32 7)
  %a.ok = icmp eq i32 %a, 32
  %b.ok = icmp eq i32 %b, 23
  %c.ok = icmp eq i32 %c, 11
  %d.ok = icmp eq i32 %d, 27
  %ab = and i1 %a.ok, %b.ok
  %cd = and i1 %c.ok, %d.ok
  %all = and i1 %ab, %cd
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}} = private unnamed_addr constant
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64

; CHECK-LABEL: define i32 @poly_alpha(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK: call i32 %poly_alpha.obf.wrapper.indirect(i32 %x, i64 %poly_alpha.obf.wrapper.token)
; CHECK-LABEL: define i32 @poly_beta(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK: call i32 %poly_beta.obf.wrapper.indirect(i32 %x, i64 %poly_beta.obf.wrapper.token)
; CHECK-LABEL: define i32 @poly_gamma(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK: call i32 %poly_gamma.obf.wrapper.indirect(i32 %x, i64 %poly_gamma.obf.wrapper.token)
; CHECK-LABEL: define i32 @poly_delta(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK: call i32 %poly_delta.obf.wrapper.indirect(i32 %x, i64 %poly_delta.obf.wrapper.token)

; CHECK: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(
; CHECK: define internal i32 @__obf_vm_e_{{[A-Za-z0-9_]+}}(
; CHECK: obf.vm.entry.thunk:
; CHECK: ret i32
; CHECK-DAG: "vm.entry.thunk.shape.decoy_indirect"
; CHECK-DAG: "vm.entry.thunk.shape.indirect"
; CHECK-NOT: "vm.entry.thunk.shape.direct"
; CHECK-NOT: "vm.entry.thunk.shape.neutral"
