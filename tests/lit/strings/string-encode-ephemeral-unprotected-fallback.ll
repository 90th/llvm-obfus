; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-unprotected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-ephemeral-unprotected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.shared_str = private unnamed_addr constant [6 x i8] c"hello\00"

; Protected function reads a byte from the shared string literal.
; Validates that a string shared between protected and unprotected functions in the same TU
; falls back to helper_global_ctor so unprotected callers observe valid plaintext at runtime.
define i32 @check_byte() {
entry:
  %c = load i8, ptr getelementptr inbounds ([6 x i8], ptr @.shared_str, i64 0, i64 0), align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}

; Unprotected function reads whole string pointer
define ptr @public_export() {
entry:
  ret ptr @.shared_str
}

define i32 @main() {
entry:
  ; Verify unprotected caller receives decrypted plaintext at runtime
  %str = call ptr @public_export()
  %c = load i8, ptr %str, align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}
; CHECK: @.shared_str = private unnamed_addr global [6 x i8]
; CHECK: @llvm.global_ctors = appending global
; CHECK: define internal void @__obf_str_d_
