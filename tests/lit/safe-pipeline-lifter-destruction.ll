; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-lifter-destruction.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-lifter-destruction.yaml -passes=obf-safe-pipeline -S %s -o - | %llc -mtriple=x86_64-unknown-linux-gnu -o - | %FileCheck %s --check-prefix=ASM

target triple = "x86_64-unknown-linux-gnu"

define i32 @vm_target(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @vm_target(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; IR-DAG: call void asm sideeffect ".Lobf_ld_
; IR-DAG: .cfi_lsda 0x1b, .Lobf_ld_
; IR-DAG: .pushsection .gcc_except_table,
; IR-DAG: .byte 0x0f, 0x85;
; IR-DAG: .byte 0xff, 0xe0, 0x0f, 0x0b;
; IR-LABEL: define i32 @main()
; IR: call i32 %{{[^ ]+}}(i32 0, i64 %{{[^)]+}})
; IR: define internal i32 @{{[^ ]+}}(i32

; ASM: .cfi_lsda 27, .Lobf_ld_
; ASM: .section	.gcc_except_table,"a",@progbits
; ASM: .uleb128 .Lobf_ld_
; ASM: _poison_mid-.Lobf_ld_
; ASM: callq	.Lobf_ld_
; ASM: jmpq	*%rax
