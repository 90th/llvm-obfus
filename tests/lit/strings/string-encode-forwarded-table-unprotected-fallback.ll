; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-forwarded-table-unprotected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-forwarded-table-unprotected.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

@.shared_str = private constant [6 x i8] c"hello\00", align 1
@.forward_table = private constant [1 x ptr] [ptr @.shared_str], align 8

; Protected function reads a byte through a local constant forwarded pointer table
define i32 @check_protected() {
entry:
  %slot = getelementptr inbounds [1 x ptr], ptr @.forward_table, i64 0, i64 0
  %p = load ptr, ptr %slot, align 8
  %c = load i8, ptr %p, align 1
  %is_h = icmp eq i8 %c, 104
  %res = select i1 %is_h, i32 0, i32 1
  ret i32 %res
}

; Unprotected function reads whole string pointer through the forwarded pointer table
define ptr @public_export() {
entry:
  %slot = getelementptr inbounds [1 x ptr], ptr @.forward_table, i64 0, i64 0
  %p = load ptr, ptr %slot, align 8
  ret ptr %p
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

; CHECK: @.shared_str = private global [6 x i8]
; CHECK: @llvm.global_ctors = appending global
; CHECK: define internal void @__obf_str_d_
