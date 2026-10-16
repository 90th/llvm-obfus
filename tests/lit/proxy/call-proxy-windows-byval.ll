; Explicit LLVM byval is a distinct row from MSVC's ordinary indirect aggregate
; input. The former is unqualified for Windows private musttail edges in LLVM 22.
; Keep the original attribute and fail admission before backend lowering; do not
; strip byval or silently replace it with the qualified ordinary-pointer row.
;
; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-windows-byval.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=DIAGNOSTIC
; RUN: %FileCheck %s --check-prefix=LEDGER < %t.coverage.json
;
; DIAGNOSTIC: Windows byval forwarding is not qualified
; LEDGER: unsupported_win64_byval

target triple = "x86_64-pc-windows-msvc"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
%Big = type { i64, i64, i64 }

define void @windows_byval_target(i64 %tag, ptr sret(%Big) align 8 %output, ptr byval(%Big) align 8 %input) noinline {
entry:
  %value = load i64, ptr %input, align 8
  %result = add i64 %value, %tag
  store i64 %result, ptr %output, align 8
  ret void
}

define void @proxy_windows_byval(ptr %output, ptr %input) noinline {
entry:
  call void @windows_byval_target(i64 7, ptr sret(%Big) align 8 %output, ptr byval(%Big) align 8 %input)
  ret void
}
