; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "string_encoding") | [.target_name, .status, (.count | tostring), .strategy.kind] | join("|")' | %FileCheck %s

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.ephem = private unnamed_addr constant [6 x i8] c"ephem\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @main() {
entry:
  %result = call i32 @first_char(ptr @.secret)
  %cmp = call i32 @bcmp(ptr @.ephem, ptr @.ephem, i64 5)
  %ok = icmp eq i32 %cmp, 0

  ret i32 %result
}

; CHECK-DAG: .secret|candidate|1|helper_lazy_decode
; CHECK-DAG: .ephem|candidate|2|inline_stack_decode
