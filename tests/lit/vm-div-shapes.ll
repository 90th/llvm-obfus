; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-div-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-div-shapes.yaml -passes=obf-vm -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-div-shapes.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @const_udiv_pow2(i32 %x) {
entry:
  %div = udiv i32 %x, 8
  ret i32 %div
}

define i32 @const_urem_pow2(i32 %x) {
entry:
  %rem = urem i32 %x, 8
  ret i32 %rem
}

define i32 @const_udiv_nonpow2(i32 %x) {
entry:
  %div = udiv i32 %x, 7
  ret i32 %div
}

define i32 @var_udiv(i32 %x, i32 %y) {
entry:
  %div = udiv i32 %x, %y
  ret i32 %div
}

define i32 @main() {
entry:
  %a = call i32 @const_udiv_pow2(i32 40)
  %b = call i32 @const_urem_pow2(i32 42)
  %c = call i32 @const_udiv_nonpow2(i32 42)
  %d = call i32 @var_udiv(i32 42, i32 7)
  %a.ok = icmp eq i32 %a, 5
  %b.ok = icmp eq i32 %b, 2
  %c.ok = icmp eq i32 %c, 6
  %d.ok = icmp eq i32 %d, 6
  %ab = and i1 %a.ok, %b.ok
  %cd = and i1 %c.ok, %d.ok
  %ok = and i1 %ab, %cd
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_
; CHECK-DAG: %obf.vm.udiv.lhs = {{(xor|add) i32}}
; CHECK-DAG: %obf.vm.udiv = lshr i32 %obf.vm.udiv.lhs, 3
; CHECK-DAG: %obf.vm.urem.lhs = {{(xor|add) i32}}
; CHECK-DAG: %obf.vm.urem = and i32 %obf.vm.urem.lhs, 7
; CHECK-DAG: %obf.vm.udiv = udiv i32 %obf.vm.slot, 7
; CHECK-DAG: %obf.vm.udiv = udiv i32 %obf.vm.slot, %obf.vm.slot
