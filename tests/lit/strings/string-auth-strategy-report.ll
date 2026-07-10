; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-encode-auth-lazy.yaml -passes=obf-feature-report -disable-output %s | jq -r '(.transforms[] | select(.pass == "string_encoding") | [.target_name, .status, (.count|tostring), .detail, (.strategy.kind // ""), (.strategy.helper_shape // ""), (.strategy.key_schedule // "")] | join("|"))' | %FileCheck %s

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
  %result = call i32 @first_char(ptr @.secret)
  ret i32 %result
}

; CHECK: .secret|applied|1|lazy_decode: 1 lazy use(s)|helper_lazy_decode|lazy_auth_runtime_v3|blake2s_keyed_auth_v3
