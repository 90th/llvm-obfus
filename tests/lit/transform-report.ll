; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/transform-report.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s

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

; CHECK-DAG: "count":3,"detail":"eligible: 3 virtual instruction(s) across 1 block(s)","pass":"vm","status":"applied","target_kind":"function","target_name":"vm_me"
; CHECK-DAG: "count":0,"detail":"suppressed after vm","pass":"constant_encoding","status":"skipped","target_kind":"function","target_name":"vm_me"
; CHECK-DAG: "count":0,"detail":"suppressed after vm","pass":"block_split","status":"skipped","target_kind":"function","target_name":"vm_me"
; CHECK-DAG: "count":3,"detail":"eligible: 3 virtual instruction(s) across 1 block(s)","pass":"vm","status":"applied","target_kind":"function","target_name":"strong_vm_me"
; CHECK-DAG: "count":0,"detail":"policy disallows split","pass":"block_split","status":"skipped","target_kind":"function","target_name":"strong_vm_me"
; CHECK-DAG: "count":0,"detail":"policy disallows constant encoding","pass":"constant_encoding","status":"skipped","target_kind":"function","target_name":"strong_vm_me"
; CHECK-DAG: "count":0,"detail":"deferred to vm hardening","pass":"instruction_substitution","status":"skipped","target_kind":"function","target_name":"strong_vm_me"
; CHECK-DAG: "count":0,"detail":"deferred to vm hardening","pass":"control_flattening","status":"skipped","target_kind":"function","target_name":"strong_vm_me"
; CHECK-DAG: "count":1,"detail":"1 split(s) available","pass":"block_split","status":"applied","target_kind":"function","target_name":"split_me"
; CHECK-DAG: "count":0,"detail":"policy disallows split","pass":"block_split","status":"skipped","target_kind":"function","target_name":"keep_plain"
; CHECK-DAG: "count":1,"detail":"1 constant(s) available","pass":"constant_encoding","status":"applied","target_kind":"function","target_name":"main"
; CHECK: "detail":"lazy_decode: 1 lazy use(s)"{{.*}}"kind":"helper_lazy_decode"{{.*}}"target_name":".secret"
; CHECK: "detail":"not referenced by protected function"{{.*}}"kind":"none"{{.*}}"target_name":".plain"
