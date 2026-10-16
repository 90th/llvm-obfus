; This target-specific admission test runs on either host: no Windows code is
; executed. Both C and Fast use indirect vector parameter lowering on Win64;
; LLVM 22 private musttail forwarding failed native runtime equivalence.
;
; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-windows-vector.yaml -passes=obf-safe-pipeline -S %s -o %t.ll
; RUN: %FileCheck %s --check-prefix=LEDGER < %t.coverage.json
; RUN: %FileCheck %s --check-prefix=ORIGINAL < %t.ll
;
; Exactly four selected live edges remain unsupported, rather than any being
; emitted, silently omitted, converted to pointers, or stripped of their ABI.
; LEDGER-COUNT-4: code=unsupported_win64_vector,
; LEDGER-NOT: code=unsupported_win64_vector,
; ORIGINAL-NOT: obf.call.proxy
; ORIGINAL-LABEL: define <4 x float> @proxy_windows_vector_c_stateful(
; ORIGINAL: call <4 x float> @vector_target(
; ORIGINAL-LABEL: define <4 x float> @proxy_windows_vector_c_tail(
; ORIGINAL: musttail call <4 x float> @vector_target(
; ORIGINAL-LABEL: define fastcc <4 x i32> @proxy_windows_vector_fast_stateful(
; ORIGINAL: call fastcc <4 x i32> @fast_vector_target(
; ORIGINAL-LABEL: define fastcc <4 x i32> @proxy_windows_vector_fast_tail(
; ORIGINAL: musttail call fastcc <4 x i32> @fast_vector_target(

target triple = "x86_64-pc-windows-msvc"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"

declare <4 x float> @vector_target(<4 x float>)
declare fastcc <4 x i32> @fast_vector_target(<4 x i32>)

define <4 x float> @proxy_windows_vector_c_stateful(<4 x float> %input) noinline {
  %result = call <4 x float> @vector_target(<4 x float> %input)
  ret <4 x float> %result
}
define <4 x float> @proxy_windows_vector_c_tail(<4 x float> %input) noinline {
  %result = musttail call <4 x float> @vector_target(<4 x float> %input)
  ret <4 x float> %result
}
define fastcc <4 x i32> @proxy_windows_vector_fast_stateful(<4 x i32> %input) noinline {
  %result = call fastcc <4 x i32> @fast_vector_target(<4 x i32> %input)
  ret <4 x i32> %result
}
define fastcc <4 x i32> @proxy_windows_vector_fast_tail(<4 x i32> %input) noinline {
  %result = musttail call fastcc <4 x i32> @fast_vector_target(<4 x i32> %input)
  ret <4 x i32> %result
}
