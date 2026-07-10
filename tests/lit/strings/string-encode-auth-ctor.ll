; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.plain = private unnamed_addr constant [6 x i8] c"plain\00"

define ptr @leak_secret() {
entry:
  ret ptr @.secret
}

define i32 @main() {
entry:
  %secret.ptr = getelementptr inbounds [7 x i8], ptr @.secret, i64 0, i64 0
  %first = load i8, ptr %secret.ptr
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define ptr @get_plain() {
entry:
  ret ptr @.plain
}

; IR: @.secret = private unnamed_addr global [7 x i8] zeroinitializer
; IR-NOT: c"secret\00"
; IR: @__obf_string_ct__secret = internal constant [7 x i8]
; IR: @__obf_string_destination_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_ciphertext_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_build_key_ref__secret = internal constant { i64, ptr }
; IR: @__obf_string_state_ref__secret = internal global { i64, i64 }
; IR: @__obf_string_desc__secret = internal constant { i32, i32, i64, i64, i64, i64, i64, i64, i64, i64, i64, [16 x i8], [16 x i8], ptr, ptr, ptr, ptr } { i32 2, i32 1, i64 7
; IR-SAME: ptr @__obf_string_destination_ref__secret, ptr @__obf_string_ciphertext_ref__secret, ptr @__obf_string_build_key_ref__secret, ptr @__obf_string_state_ref__secret }
; IR: @llvm.global_ctors = appending global
; IR: define internal void @__obf_decode__secret() {
; IR: call ptr @rt_core_sd2(ptr @__obf_string_desc__secret, i64 7, i64
