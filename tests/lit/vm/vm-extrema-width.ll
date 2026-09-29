; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-width.yaml -passes=obf-feature-report -disable-output %s | jq -r '.transforms[] | select(.pass == "vm") | [.target_name, .status, (.count | tostring), .detail] | join("|")' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-width.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --check-prefix=SKIPPED --implicit-check-not='@__obf_vm_bc_'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-width-strong.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRICT

; 8388608 is LLVM's maximum legal integer bit width. The ordered comparison
; handler cannot form the 8388609-bit type used for its widened subtraction.
declare i8388608 @llvm.umax.i8388608(i8388608, i8388608)

define i8388608 @vm_wide_max(i8388608 %lhs, i8388608 %rhs) {
entry:
  %max = call i8388608 @llvm.umax.i8388608(i8388608 %lhs, i8388608 %rhs)
  ret i8388608 %max
}

define i1 @vm_wide_ordered_cmp(i8388608 %lhs, i8388608 %rhs) {
entry:
  %less = icmp ult i8388608 %lhs, %rhs
  ret i1 %less
}

; REPORT-DAG: vm_wide_max|skipped|0|integer comparison width exceeds VM widening limit
; REPORT-DAG: vm_wide_ordered_cmp|skipped|0|integer comparison width exceeds VM widening limit
; SKIPPED-LABEL: define i8388608 @vm_wide_max(
; SKIPPED: call i8388608 @llvm.umax.i8388608
; SKIPPED-LABEL: define i1 @vm_wide_ordered_cmp(
; SKIPPED: icmp ult i8388608
; STRICT: LLVM ERROR: strong_vm invariant violation: function vm_wide_max was not virtualized
; STRICT-SAME: reason=integer comparison width exceeds VM widening limit
