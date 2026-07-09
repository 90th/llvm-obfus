; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-cfg-state-tamper.yaml -passes='obf-string-encode,obf-control-flatten,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t
; RUN: %python %S/../Inputs/tamper_string_auth_ir.py %t __obf_string_desc__secret state
; RUN: not --crash %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.branch = internal global i1 true

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %cond = load volatile i1, ptr @.branch
  br i1 %cond, label %left, label %right

left:
  %left_result = call i32 @first_char(ptr @.secret)
  ret i32 %left_result

right:
  ret i32 1
}
