; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/transform-report.yaml -passes=obf-feature-report -disable-output %s | jq -r '.schema, (.transforms[] | [.target_name, .pass, .status, (.count|tostring), .detail, (.strategy.kind // ""), (.strategy.helper_shape // ""), (.strategy.fallback_reason // "")] | join("|"))' | %FileCheck %s

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"
@.plain = private unnamed_addr constant [6 x i8] c"plain\00"

define i32 @split_me(i32 %x) {
entry:
  %a = add i32 %x, 7
  %b = add i32 %a, 11
  ret i32 %b
}

define ptr @keep_plain() {
entry:
  ret ptr @.plain
}

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @vm_me(i32 %x) {
entry:
  %a = xor i32 %x, 4660
  %b = add nsw i32 %a, 85
  ret i32 %b
}

define i32 @strong_vm_me(i32 %x) {
entry:
  %a = xor i32 %x, 8738
  %b = add nsw i32 %a, 17
  ret i32 %b
}

define i32 @main() {
entry:
  %result = call i32 @first_char(ptr @.secret)
  ret i32 42
}

; CHECK: obf.feature_report.v3
; CHECK-DAG: vm_me|vm|applied|3|eligible: 3 virtual instruction(s) across 1 block(s)|
; CHECK-DAG: vm_me|constant_encoding|skipped|0|suppressed after vm|
; CHECK-DAG: vm_me|block_split|skipped|0|suppressed after vm|
; CHECK-DAG: strong_vm_me|vm|applied|3|eligible: 3 virtual instruction(s) across 1 block(s)|
; CHECK-DAG: strong_vm_me|block_split|skipped|0|policy disallows split|
; CHECK-DAG: strong_vm_me|constant_encoding|skipped|0|policy disallows constant encoding|
; CHECK-DAG: strong_vm_me|instruction_substitution|skipped|0|deferred to vm hardening|
; CHECK-DAG: strong_vm_me|control_flattening|skipped|0|deferred to vm hardening|
; CHECK-DAG: split_me|block_split|applied|1|1 split(s) available|
; CHECK-DAG: split_me|constant_encoding|applied|1|1 constant(s) available|
; CHECK-DAG: keep_plain|block_split|skipped|0|no viable blocks to split|
; CHECK-DAG: main|block_split|applied|1|1 split(s) available|
; CHECK-DAG: main|constant_encoding|applied|1|1 constant(s) available|
; CHECK-DAG: .secret|string_encoding|applied|1|lazy_decode: 1 isolated lazy use(s)|helper_lazy_decode|{{(lazy_flag_reverse_v1|lazy_flag_unrolled_v0)}}|
; CHECK-DAG: .plain|string_encoding|applied|1|lazy_decode: 1 lazy use(s)|helper_lazy_decode|{{(lazy_flag_reverse_v1|lazy_flag_unrolled_v0)}}|
