; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-data-anchor-decoys.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-data-anchor-decoys.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; decoy_target has enough instructions (~10 arith + logic ops) to produce
; bytecode >= 32 bytes, which triggers decoy anchor generation (pr27.5+).
define i32 @decoy_target(i32 %x, i32 %y, i32 %z) {
entry:
  %a0 = add i32 %x, %y
  %a1 = mul i32 %a0, %z
  %a2 = xor i32 %a0, %a1
  %a3 = add i32 %a2, 42
  %a4 = sub i32 %a1, %x
  %a5 = and i32 %a3, %a4
  %a6 = or i32 %a2, %a5
  %a7 = mul i32 %a6, 3
  %a8 = xor i32 %a7, %z
  %a9 = add i32 %a8, 100
  ret i32 %a9
}

define i32 @main() {
entry:
  %r = call i32 @decoy_target(i32 3, i32 5, i32 7)
  %ok = icmp eq i32 %r, 251
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; real anchor global (base name without suffix)
; CHECK-DAG: @[[BC0:__obf_vm_bc_i_[A-Za-z0-9_]+]] = private unnamed_addr constant

; at least one real clone anchor (_a suffix)
; CHECK-DAG: @{{__obf_vm_bc_i_[A-Za-z0-9_]+_a[0-9A-Fa-f]+}} = private unnamed_addr constant

; at least one decoy anchor (_d suffix) — content-identical but named distinctly
; CHECK-DAG: @{{__obf_vm_bc_i_[A-Za-z0-9_]+_d[0-9A-Fa-f]+}} = private unnamed_addr constant

; vm implementation function present with non-local predicate split
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i32 %z, i64 %obf.hidden_token)
; CHECK: %obf.vm.pred.slot = alloca i32
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot

; anchor scattering and decoy attributes must both be present
; CHECK-DAG: "vm.bytecode.anchor.scattered"
; CHECK-DAG: "vm.bytecode.anchor.decoys"
; CHECK-DAG: "vm.bytecode.anchor.count.{{[3-9][0-9]*}}"
; CHECK-DAG: "vm.bytecode.anchor.real.{{[2-9][0-9]*}}"
; CHECK-DAG: "vm.bytecode.anchor.decoy.{{[1-9][0-9]*}}"

; handler route trampoline must be present (routed handler mapping)
; CHECK-DAG: "vm.handler.route.trampoline"
