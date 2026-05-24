; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/lifter-destruction.yaml -passes=obf-lifter-destruction -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/lifter-destruction.yaml -passes=obf-lifter-destruction -S %s -o - | %llc -mtriple=x86_64-unknown-linux-gnu -o - | %FileCheck %s --check-prefix=ASM

target triple = "x86_64-unknown-linux-gnu"

define i32 @target(i32 %x) {
entry:
  %cmp = icmp sgt i32 %x, 4
  br i1 %cmp, label %hot, label %cold

hot:
  %hotv = add i32 %x, 7
  ret i32 %hotv

cold:
  %coldv = sub i32 %x, 3
  ret i32 %coldv
}

; IR-LABEL: define i32 @target
; IR: call void asm sideeffect ".Lobf_ld_
; IR-SAME: call .Lobf_ld_
; IR-SAME: popq %rax; movl $$(.Lobf_ld_
; IR-SAME: addq %rcx, %rax; jmpq *%rax;
; IR-SAME: .byte 0x0f, 0x85;
; IR-SAME: .byte 0xff, 0xe0, 0x0f, 0x0b;
; IR-SAME: .cfi_lsda 0x1b, .Lobf_ld_
; IR-SAME: .pushsection .gcc_except_table,
; IR-SAME: .uleb128 .Lobf_ld_
; IR-SAME: _poison_mid-.Lobf_ld_
; IR-SAME: ", "~{rax},~{rcx},~{cc},~{memory}"()

; ASM-LABEL: target:
; ASM: callq	.Lobf_ld_
; ASM: popq	%rax
; ASM: movl	$.Lobf_ld_
; ASM-SAME: _resume-.Lobf_ld_
; ASM-SAME: _retaddr, %ecx
; ASM: addq	%rcx, %rax
; ASM: jmpq	*%rax
; ASM: .byte	15
; ASM: .byte	133
; ASM: .byte	255
; ASM: .byte	224
; ASM: .byte	15
; ASM: .byte	11
; ASM: .cfi_lsda 27, .Lobf_ld_
; ASM: .section	.gcc_except_table,"a",@progbits
; ASM: .uleb128 .Lobf_ld_
; ASM: .uleb128 .Lobf_ld_
; ASM: .uleb128 .Lobf_ld_
; ASM: _poison_mid-.Lobf_ld_
