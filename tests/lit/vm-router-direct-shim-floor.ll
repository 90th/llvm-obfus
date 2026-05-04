; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-router-direct-shim-floor.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-router-direct-shim-floor.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; multi-entry normal vm routing must not keep weak direct or neutral entry thunks.
; the routed path should stay on indirect or decoy-indirect thunks for this seed.

define i32 @floor_alpha(i32 %x) {
entry:
  %a = xor i32 %x, 13
  %b = add i32 %a, 2
  ret i32 %b
}

define i32 @floor_beta(i32 %x) {
entry:
  %a = mul i32 %x, 5
  %b = add i32 %a, 1
  ret i32 %b
}

define i32 @floor_gamma(i32 %x) {
entry:
  %a = sub i32 %x, 4
  %b = xor i32 %a, 19
  ret i32 %b
}

define i32 @floor_delta(i32 %x) {
entry:
  %a = shl i32 %x, 1
  %b = add i32 %a, 9
  ret i32 %b
}

define i32 @main() {
entry:
  %a = call i32 @floor_alpha(i32 7)
  %b = call i32 @floor_beta(i32 3)
  %c = call i32 @floor_gamma(i32 10)
  %d = call i32 @floor_delta(i32 4)
  %a.ok = icmp eq i32 %a, 12
  %b.ok = icmp eq i32 %b, 16
  %c.ok = icmp eq i32 %c, 21
  %d.ok = icmp eq i32 %d, 17
  %ab = and i1 %a.ok, %b.ok
  %cd = and i1 %c.ok, %d.ok
  %ok = and i1 %ab, %cd
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @floor_alpha(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @floor_beta(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @floor_gamma(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @floor_delta(i32 %x)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @main()

; CHECK-DAG: obf.vm.entry.thunk.iptr
; CHECK-DAG: obf.vm.entry.thunk.decoy.iptr
; CHECK-DAG: "vm.entry.thunk.shape.indirect"
; CHECK-DAG: "vm.entry.thunk.shape.decoy_indirect"
; CHECK-NOT: "vm.entry.thunk.shape.direct"
; CHECK-NOT: "vm.entry.thunk.shape.neutral"
; CHECK-NOT: call i32 @__obf_vm_i_