; RUN: %opt -load-pass-plugin %obf_plugin -passes=obf-entropy-init -S %s -o - | %FileCheck %s --check-prefix=ENTROPY
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-properties.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-properties.yaml -passes=obf-control-flatten -S %s -o - | %FileCheck %s --check-prefix=FLAT

@__obf_entropy_anchor = global i64 0, align 8
@__obf_entropy_anchor_ref = global ptr @__obf_entropy_anchor, align 8

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

; ENTROPY: @__obf_entropy_anchor = global i64 {{-?[1-9][0-9]*}}, align 8

; VM-LABEL: define internal i32 @__obf_vm_impl_alpha_add(i32 %x, i64 %obf.hidden_token)
; VM: {{^vm\.0:}}
; VM: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8 {{[^,]+}}, [[ALPHA_OP:-?[0-9]+]]
; VM: {{^vm\.exec\.0:}}
; VM-LABEL: define internal i32 @__obf_vm_impl_beta_add(i32 %x, i64 %obf.hidden_token)
; VM: {{^vm\.0:}}
; VM-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8 {{[^,]+}}, [[ALPHA_OP]]
; VM: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8 {{[^,]+}}, [[BETA_OP:-?[0-9]+]]
; VM: {{^vm\.exec\.0:}}

; FLAT-LABEL: define i32 @flatten_me(i32 %x)
; FLAT: switch i32 %obf.state
; FLAT: label %obf.flat.decoy
; FLAT: obf.flat.decoy:
; FLAT: obf.flat.decoy.loop:
; FLAT: obf.flat.decoy.trap:
; FLAT: call void @llvm.trap()
