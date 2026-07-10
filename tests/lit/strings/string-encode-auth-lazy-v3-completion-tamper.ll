; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %python %S/../Inputs/tamper_string_auth_ir.py %t auto clear-completion-before-second-call
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define ptr @first_use() {
entry:
  ret ptr @.secret
}

define ptr @second_use() {
entry:
  ret ptr @.secret
}

define i32 @main() {
entry:
  %first_ptr = call ptr @first_use()
  %first = call i32 @first_char(ptr %first_ptr)
  %second_ptr = call ptr @second_use()
  %second = call i32 @first_char(ptr %second_ptr)
  %sum = add i32 %first, %second
  ret i32 %sum
}

; IR: @__obf_string_state_ref_
; IR: @__obf_string_topology_
; IR: define internal ptr @__obf_family_auth_v3(
; IR: call ptr @rt_core_sd3(
