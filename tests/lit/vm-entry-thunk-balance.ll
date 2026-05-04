; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunk-balance.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunk-balance.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; seed 1 maps alpha -> neutral and beta -> direct in the raw per-binding selector.
; the module-local rebalance must still force at least one high-hardening entry thunk.
; CHECK-DAG: "vm.entry.thunk.shape.{{(indirect|decoy_indirect)}}"

define i32 @alpha(i32 %x) {
entry:
  %sum = add i32 %x, 7
  ret i32 %sum
}

define i32 @beta(i32 %x) {
entry:
  %prod = mul i32 %x, 5
  ret i32 %prod
}

define i32 @main() {
entry:
  %a = call i32 @alpha(i32 3)
  %b = call i32 @beta(i32 4)
  %a.ok = icmp eq i32 %a, 10
  %b.ok = icmp eq i32 %b, 20
  %ok = and i1 %a.ok, %b.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}