; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %first.ptr = call ptr @first_use()
  %first = call i32 @first_char(ptr %first.ptr)
  %second.ptr = call ptr @second_use()
  %second = call i32 @first_char(ptr %second.ptr)
  %sum = add i32 %first, %second
  ret i32 %sum
}

define ptr @first_use() {
entry:
  ret ptr @.secret
}

define ptr @second_use() {
entry:
  ret ptr @.secret
}

; IR-LABEL: define ptr @first_use() {
; IR: call ptr @__obf_family_auth_v3(ptr @__obf_string_desc__secret, i32 0, i32 0, i64 7, i64
; IR-LABEL: define ptr @second_use() {
; IR: call ptr @__obf_family_auth_v3(ptr @__obf_string_desc__secret, i32 0, i32 0, i64 7, i64
; IR-LABEL: define internal ptr @__obf_family_auth_v3(ptr %desc, i32 %cfg_state, i32 %expected_state, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology) {
; IR: %obf.str.cfg.match = icmp eq i32 %cfg_state, %expected_state
; IR: br i1 %obf.str.cfg.match, label %decode, label %state_mismatch
; IR: state_mismatch:
; IR: call void @llvm.trap()
; IR: unreachable
; IR: decode:
; IR: call ptr @rt_core_sd3(ptr %desc, i64 %trusted_length, i64 %trusted_binding, ptr %trusted_topology)
