; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/lifter-destruction.yaml -passes=obf-lifter-destruction -S %s -o - | %FileCheck %s --check-prefix=ARM

target triple = "aarch64-unknown-linux-gnu"

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

; ARM-LABEL: define i32 @target
; ARM-NOT: call void asm sideeffect
; ARM-NOT: %obf.lifter.true =
