; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-opcode-predicate-splitting.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-opcode-predicate-splitting.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @split_me(i32 %x) {
entry:
  %a = xor i32 %x, 123
  %b = add i32 %a, 17
  ret i32 %b
}

define i32 @main() {
entry:
  %result = call i32 @split_me(i32 5)
  %ok = icmp eq i32 %result, 143
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: trap.obf.vm:
; CHECK: obf.vm.fail.shared:
; CHECK: br label %trap.obf.vm
; CHECK: {{^vm\.0:}}
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK: {{%obf\.vm\.opcode\.split\.low\.actual[^ ]* = }}and i32
; CHECK: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK: {{%obf\.vm\.opcode\.split\.high\.actual[^ ]* = }}lshr i32
; CHECK: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK: {{%obf\.vm\.opcode\.split\.match[^ ]* = }}and i1
; CHECK: br i1 {{[^,]+}}, label %vm.exec.0, label %obf.vm.fail.shared
