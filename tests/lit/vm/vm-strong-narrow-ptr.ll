; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-pointer-materialization-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s

target datalayout = "e-m:e-p:16:16:16-i32:32:32-a:0:32-n32-S64"

define i32 @strong_target_a(i32 %x) {
entry:
  %sum = add i32 %x, 42
  ret i32 %sum
}

; CHECK-LABEL: define i32 @strong_target_a(i32 %x)
; CHECK-NOT: {{.*}}.ptrmat.direct
; CHECK-NOT: {{.*}}.ptrmat.split
; CHECK: {{.*}}.ptrmat.addsub
; CHECK: ret i32