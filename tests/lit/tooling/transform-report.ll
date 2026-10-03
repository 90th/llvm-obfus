; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/transform-report.yaml -passes=obf-feature-report -disable-output %s > %t.predictions.json
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/transform-report.yaml -passes='obf-coverage-start,obf-coverage-report' -disable-output %s > %t.coverage.json
; RUN: env -u OBF_COVERAGE_REPORT %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/transform-report.yaml -passes=obf-coverage-report -disable-output %s > %t.uncaptured.json
; RUN: %python %S/../Inputs/report_contract.py predictions %t.predictions.json --coverage %t.coverage.json --uncaptured %t.uncaptured.json

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

