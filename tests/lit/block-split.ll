; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/block-split.yaml -passes=obf-block-split -S %s -o - | %FileCheck %s

define i32 @split_me(i32 %x) {
entry:
  %a = add i32 %x, 1
  %b = add i32 %a, 2
  %c = add i32 %b, 3
  ret i32 %c
}

define i32 @keep_me(i32 %x) {
entry:
  ret i32 %x
}

; CHECK-LABEL: define i32 @split_me
; CHECK: entry:
; CHECK: %a = add i32 %x, 1
; CHECK: br label %entry.obf.split
; CHECK: entry.obf.split:
; CHECK: ret i32 %c

; CHECK-LABEL: define i32 @keep_me
; CHECK: entry:
; CHECK-NEXT: ret i32 %x
