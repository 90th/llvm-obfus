; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/artifact-cleanup-release.yaml -passes=obf-artifact-cleanup -S %s -o - | %FileCheck %s

@.obf.strong_vm = private unnamed_addr constant [14 x i8] c"obf:strong_vm\00", section "llvm.metadata"
@.annotation.file = private unnamed_addr constant [15 x i8] c"annotations.ll\00", section "llvm.metadata"
@llvm.global.annotations = appending global [1 x { ptr, ptr, ptr, i32, ptr }] [
  { ptr, ptr, ptr, i32, ptr } { ptr @target, ptr @.obf.strong_vm, ptr @.annotation.file, i32 1, ptr null }
], section "llvm.metadata"

define void @target() {
entry:
  ret void
}

; CHECK-LABEL: define void @target()
; CHECK-NOT: llvm.global.annotations
; CHECK-NOT: llvm.metadata
; CHECK-NOT: obf:strong_vm
; CHECK-NOT: @.obf.strong_vm
; CHECK-NOT: @.annotation.file
