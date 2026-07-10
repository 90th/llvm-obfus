; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-ctor.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t
; RUN: %python %S/../Inputs/tamper_string_auth_ir.py %t __obf_string_desc__secret cache-status
; RUN: not --crash %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @main() {
entry:
  %first = load i8, ptr @.secret
  %ok = icmp eq i8 %first, 115
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
