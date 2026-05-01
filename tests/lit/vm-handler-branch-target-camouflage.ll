; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-handler-branch-target-camouflage.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-handler-branch-target-camouflage.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @route_me(i32 %x) {
entry:
  %a = xor i32 %x, 77
  %b = add i32 %a, 9
  ret i32 %b
}

define i32 @main() {
entry:
  %result = call i32 @route_me(i32 5)
  %ok = icmp eq i32 %result, 81
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.pred.slot = alloca i32
; CHECK: {{^vm\.0:}}
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK: br label %obf.vm.opcode.pred.merge
; CHECK: {{^obf\.vm\.opcode\.pred\.merge[0-9]*:}}
; CHECK: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; CHECK: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; CHECK: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; CHECK-NEXT: br label %vm.exec.{{[0-9]+}}
