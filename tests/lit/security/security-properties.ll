; RUN: %opt -load-pass-plugin %obf_plugin -passes=obf-entropy-init -S %s -o - | %FileCheck %s --check-prefix=ENTROPY
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-properties.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-properties.yaml -passes=obf-control-flatten -S %s -o - | %FileCheck %s --check-prefix=FLAT

@rt_core_ea = global i64 0, align 8

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

define i32 @flatten_me(i32 %x) {
entry:
  %gt = icmp sgt i32 %x, 0
  br i1 %gt, label %left, label %right

left:
  %a = add i32 %x, 1
  br label %done

right:
  %b = sub i32 %x, 1
  br label %done

done:
  %r = phi i32 [ %a, %left ], [ %b, %right ]
  ret i32 %r
}

; ENTROPY: @rt_core_ea = global i64 {{-?[1-9][0-9]*}}, align 8

; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; VM: %obf.vm.pred.slot = alloca i32
; VM: {{^vm\.0:}}
; VM: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; VM-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; VM-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; VM: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; VM: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; VM: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; VM: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; VM: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; VM: br label %vm.exec.{{[0-9]+}}
; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; VM: %obf.vm.pred.slot = alloca i32
; VM: {{^vm\.0:}}
; VM: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; VM-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; VM-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; VM: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; VM: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; VM: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; VM: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; VM: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; VM: br label %vm.exec.{{[0-9]+}}

; FLAT-LABEL: define i32 @flatten_me(i32 %x)
; FLAT-NOT: switch i32 %obf.state
; FLAT-DAG: obf.flat.dispatch.eq.{{xor|affine}}
; FLAT-DAG: obf.flat.dispatch.order.{{sign|borrow}}
; FLAT-DAG: label %obf.flat.decoy{{[0-9]*}}
; FLAT-DAG: obf.flat.decoy{{[0-9]*}}:
; FLAT-DAG: obf.flat.decoy.loop{{[0-9]*}}:
; FLAT-DAG: obf.flat.decoy.trap{{[0-9]*}}:
; FLAT-DAG: call void @llvm.trap()
