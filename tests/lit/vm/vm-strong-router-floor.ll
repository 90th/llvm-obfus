; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-strong-router-floor.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-strong-router-floor.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; seed 1005 maps strong_target to a split_forward raw thunk shape before the strong_vm floor.
; the strong_vm floor must upgrade that thunk to indirect, or decoy_indirect.

define i32 @strong_target(i32 %x) {
entry:
  %xor = xor i32 %x, 42
  %sum = add i32 %xor, 7
  ret i32 %sum
}

define i32 @main() {
entry:
  %result = call i32 @strong_target(i32 5)
  %ok = icmp eq i32 %result, 54
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define i32 @strong_target(i32 %x)
; CHECK: ptrtoint (ptr @[[THUNK:__obf_vm_e_[A-Za-z0-9_]+]] to i{{[0-9]+}})
; CHECK: define internal i32 @[[THUNK]](i32 {{.*}}, i64 %obf.hidden_token)
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK: "vm.entry.thunk.shape.{{(indirect|decoy_indirect)}}"
; CHECK-NOT: "vm.entry.thunk.shape.split"
; CHECK-NOT: "vm.entry.thunk.shape.direct"
; CHECK-NOT: "vm.entry.thunk.shape.neutral"