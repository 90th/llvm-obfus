; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-opcode-scramble.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-opcode-scramble.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @alpha_add(i32 %x) {
entry:
  %sum = add i32 %x, 5
  ret i32 %sum
}

define i32 @beta_add(i32 %x) {
entry:
  %sum = add i32 %x, 5
  ret i32 %sum
}

define i32 @main() {
entry:
  %a = call i32 @alpha_add(i32 7)
  %b = call i32 @beta_add(i32 7)
  %ok1 = icmp eq i32 %a, 12
  %ok2 = icmp eq i32 %b, 12
  %ok = and i1 %ok1, %ok2
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.pred.slot = alloca i32
; CHECK: {{^vm\.[0-9]+:}}
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK: {{%obf\.vm\.opcode\.split\.high\.actual[^ ]* = }}lshr i32 {{[^,]+}}, [[ALPHA_SHIFT:[0-9]+]]
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; CHECK: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; CHECK: br label %vm.exec.{{[0-9]+}}
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: %obf.vm.pred.slot = alloca i32
; CHECK: {{^vm\.[0-9]+:}}
; CHECK: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; CHECK-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; CHECK-NOT: {{%obf\.vm\.opcode\.split\.high\.actual[^ ]* = }}lshr i32 {{[^,]+}}, [[ALPHA_SHIFT]]
; CHECK: {{%obf\.vm\.opcode\.split\.high\.actual[^ ]* = }}lshr i32 {{[^,]+}}, [[BETA_SHIFT:[0-9]+]]
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; CHECK: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; CHECK: br label %vm.exec.{{[0-9]+}}
