; Stack-backed string rewrites must invalidate an inherited ordinary `tail`
; marker. `musttail` cannot be invalidated, so it must never select a
; stack-backed decode strategy.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-inline-stack-tail.yaml -passes=obf-feature-report -disable-output %s | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name') in ('plain_tail_str','plain_musttail_str')), sep=chr(10))" | %FileCheck %s --check-prefix=PLAIN-REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-inline-stack-tail.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t.plain.ll
; RUN: %opt -passes=verify -disable-output %t.plain.ll
; RUN: %FileCheck %s --check-prefix=PLAIN-IR < %t.plain.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-inline-stack-tail-auth.yaml -passes=obf-feature-report -disable-output %s | %python -c "import json,sys; d=json.load(sys.stdin); print(*('|'.join((x['target_name'],x['status'],(x.get('strategy') or {}).get('kind',''),(x.get('strategy') or {}).get('helper_shape',''))) for x in d['transforms'] if x.get('pass') == 'string_encoding' and x.get('target_name') == 'auth_tail_str'), sep=chr(10))" | %FileCheck %s --check-prefix=AUTH-REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/string-inline-stack-tail-auth.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t.auth.ll
; RUN: %opt -passes=verify -disable-output %t.auth.ll
; RUN: %FileCheck %s --check-prefix=AUTH-IR < %t.auth.ll
;
; PLAIN-REPORT-DAG: plain_tail_str|applied|inline_stack_decode
; PLAIN-REPORT-DAG: plain_musttail_str|applied|helper_lazy_decode
;
; AUTH-REPORT: auth_tail_str|applied|inline_stack_decode|authenticated_ephemeral_stack_decode

target datalayout = "e-m:e-p:64:64-i64:64-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@plain_tail_str = private unnamed_addr constant [6 x i8] c"hello\00"
@plain_musttail_str = private unnamed_addr constant [6 x i8] c"world\00"
@auth_tail_str = private unnamed_addr constant [6 x i8] c"auth!\00"

declare i32 @strcmp(ptr, ptr)

define i32 @plain_tail(ptr %rhs) {
entry:
  %r = tail call i32 @strcmp(ptr @plain_tail_str, ptr %rhs)
  ret i32 %r
}

define i32 @plain_musttail(ptr %unused, ptr %rhs) {
entry:
  %r = musttail call i32 @strcmp(ptr @plain_musttail_str, ptr %rhs)
  ret i32 %r
}

define i32 @auth_tail(ptr %rhs) {
entry:
  %r = tail call i32 @strcmp(ptr @auth_tail_str, ptr %rhs)
  ret i32 %r
}

; PLAIN-IR-LABEL: define i32 @plain_tail(ptr %rhs)
; PLAIN-IR: %obf.inline.str = alloca [6 x i8]
; PLAIN-IR-NOT: tail call i32 @strcmp
; PLAIN-IR: call i32 @strcmp(ptr {{[^@][^,]*}}, ptr %rhs)
;
; PLAIN-IR-LABEL: define i32 @plain_musttail(ptr %unused, ptr %rhs)
; PLAIN-IR-NOT: %obf.inline.str = alloca
; PLAIN-IR: %[[LAZY:[^ ]+]] = call ptr @{{[^ (]+}}(
; PLAIN-IR: musttail call i32 @strcmp(ptr %[[LAZY]], ptr %rhs)
;
; AUTH-IR-LABEL: define i32 @auth_tail(ptr %rhs)
; AUTH-IR: %obf.auth.scratch = alloca [6 x i8]
; AUTH-IR: %[[AUTH_PTR:[^ ]+]] = call ptr @rt_core_sd3(
; AUTH-IR-NOT: tail call i32 @strcmp
; AUTH-IR: call i32 @strcmp(ptr %[[AUTH_PTR]], ptr %rhs)
