; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t
; RUN: %python %S/../Inputs/tamper_string_auth_ir.py %t __obf_string_desc__secret_a descriptor-callsite __obf_string_desc__secret_b
; RUN: not --crash %lli %t

@.secret_a = private unnamed_addr constant [7 x i8] c"secret\00"
@.secret_b = private unnamed_addr constant [7 x i8] c"second\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %left = call i32 @first_char(ptr @.secret_a)
  %right = call i32 @first_char(ptr @.secret_b)
  %sum = add i32 %left, %right
  ret i32 %sum
}

; IR: @__obf_string_desc__secret_a = internal constant
; IR: @__obf_string_desc__secret_b = internal constant
; IR: call ptr @__obf_family_auth_v2(ptr @__obf_string_desc__secret_a, i32 0, i32 0, i64 7, i64
