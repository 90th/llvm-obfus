; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/lifter-destruction.yaml -passes=obf-lifter-destruction -S %s -o - | %FileCheck %s --check-prefix=X64

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

; X64-LABEL: define i32 @target
; X64: %obf.lifter.true = icmp eq i64
; X64: %obf.lifter.cmp.lhs = zext i1 %obf.lifter.true to i64
; X64: %obf.lifter.cmp.zero =
; X64: %obf.lifter.cmp.rhs =
; X64: call void asm sideeffect "cmpq $0, $1; jne 1f; .byte 0x0f; 1:; .byte 0x1f, 0x44, 0x00, 0x00", "r,r,~{cc},~{memory}"(i64 %obf.lifter.cmp.lhs, i64 %obf.lifter.cmp.rhs)
