; REQUIRES: system-linux-x86-64
; Only the callee is selected. Every preserved incoming edge is still a proxy
; coverage obligation; default-none callers cannot hide unsupported boundaries.
;
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-preserved-required.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=REQUIRED
; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-preserved-best-effort.yaml -passes=obf-safe-pipeline -S %s -o %t.ll
; RUN: %FileCheck %s --check-prefix=LEDGER < %t.coverage.json
; RUN: %FileCheck %s --check-prefix=PRESERVED < %t.ll
;
; REQUIRED: preserved VM incoming boundary
; LEDGER-DAG: preserved_vm_invoke
; LEDGER-DAG: preserved_vm_operand_bundles
; LEDGER-DAG: preserved_vm_abi_mismatch
; LEDGER-DAG: preserved_vm_target_resolution
; PRESERVED-LABEL: define i32 @unselected_invoke(
; PRESERVED: invoke i32 @vm_callee(i32 %{{[^,)]+}})
; PRESERVED-LABEL: define i32 @unselected_bundle(
; PRESERVED: call i32 @vm_callee(i32 %[[ARG:[^,)]+]]) [ "deopt"(i32 %[[ARG]]) ]
; PRESERVED-LABEL: define i64 @unselected_mismatch(
; PRESERVED: call i64 @vm_callee(i32 %{{[^,)]+}})
; PRESERVED-LABEL: define i32 @unselected_resolution(
; PRESERVED: call i32 @vm_callee(i32 %{{[^,)]+}})

target triple = "x86_64-unknown-linux-gnu"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n8:16:32:64-S128"

declare i32 @__gxx_personality_v0(...)

define i32 @vm_callee(i32 %value) {
entry:
  %result = add i32 %value, 7
  ret i32 %result
}

define i32 @unselected_invoke(i32 %value) personality ptr @__gxx_personality_v0 {
entry:
  %result = invoke i32 @vm_callee(i32 %value) to label %done unwind label %cleanup
done:
  ret i32 %result
cleanup:
  %exception = landingpad { ptr, i32 } cleanup
  resume { ptr, i32 } %exception
}

define i32 @unselected_bundle(i32 %value) {
entry:
  %result = call i32 @vm_callee(i32 %value) [ "deopt"(i32 %value) ]
  ret i32 %result
}

define i64 @unselected_mismatch(i32 %value) {
entry:
  %result = call i64 @vm_callee(i32 %value)
  ret i64 %result
}

define i32 @unselected_resolution(i32 %value) {
entry:
  %result = call i32 @vm_callee(i32 %value)
  ret i32 %result
}
