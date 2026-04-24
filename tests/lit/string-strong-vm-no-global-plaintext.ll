; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strong-vm-no-global-plaintext.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strong-vm-no-global-plaintext.yaml -passes=obf-feature-report -disable-output %s | jq -r '(.transforms[] | select(.pass == "string_encoding") | [.target_name, .status, (.count|tostring), .detail, (.strategy.kind // ""), (.strategy.helper_shape // ""), (.strategy.fallback_reason // "")] | join("|"))' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/string-strong-vm-no-global-plaintext.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.inline = private unnamed_addr constant [3 x i8] c"ok\00"
@.skip = private unnamed_addr constant [22 x i8] c"strong-vm-skip-string\00"

declare i32 @bcmp(ptr, ptr, i64)

define i32 @strong_inline_string() {
entry:
  %cmp = call i32 @bcmp(ptr @.inline, ptr @.inline, i64 2)
  %ok = icmp eq i32 %cmp, 0
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define ptr @strong_skip_string() {
entry:
  ret ptr @.skip
}

define i32 @main() {
entry:
  %inline = call i32 @strong_inline_string()
  %ptr = call ptr @strong_skip_string()
  %first = load i8, ptr %ptr, align 1
  %skip.ok = icmp eq i8 %first, 115
  %inline.ok = icmp eq i32 %inline, 0
  %ok = and i1 %inline.ok, %skip.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-NOT: @llvm.global_ctors = appending global
; IR-NOT: @__obf_family_
; IR-NOT: @__obf_lazy_
; IR-NOT: @__obf_desc
; IR-NOT: c"ok\00"
; IR: @.skip = private unnamed_addr constant [22 x i8] c"strong-vm-skip-string\00"
; IR: %obf.inline.str = alloca [3 x i8]
; IR: call i32 @bcmp(ptr %{{[^,]+}}, ptr %{{[^,]+}}, i64 2)

; REPORT-NOT: lazy_decode
; REPORT-NOT: helper_lazy_decode
; REPORT-NOT: global_ctor
; REPORT-NOT: helper_global_ctor
; REPORT-DAG: .inline|applied|2|inline_stack_decode: 2 inline stack decode use(s)|inline_stack_decode|none|
; REPORT-DAG: .skip|skipped|0|strong_vm_no_global_plaintext: no local string strategy|none|none|strong_vm_no_global_plaintext
