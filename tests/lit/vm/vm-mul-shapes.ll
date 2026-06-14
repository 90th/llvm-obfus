; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml -passes=obf-vm -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @const_mul(i32 %x) {
entry:
  %mul = mul i32 %x, 5
  ret i32 %mul
}

define i32 @var_mul(i32 %x, i32 %y) {
entry:
  %mul = mul i32 %x, %y
  ret i32 %mul
}

define i32 @main() {
entry:
  %a = call i32 @const_mul(i32 4)
  %b = call i32 @var_mul(i32 6, i32 7)
  %a.ok = icmp eq i32 %a, 20
  %b.ok = icmp eq i32 %b, 42
  %ok = and i1 %a.ok, %b.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_
; CHECK-DAG: obf.vm.mul.term.shl
; CHECK-DAG: obf.vm.mul.acc
; CHECK-DAG: %obf.vm.mul = mul i32 %obf.vm.slot, %obf.vm.slot
; CHECK-DAG: %obf.vm.mul = {{(xor|add) i32}}
