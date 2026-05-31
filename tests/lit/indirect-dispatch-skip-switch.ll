; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch-skip-switch.yaml -passes=obf-feature-report -disable-output %s | jq -r '.transforms[] | select(.pass == "indirect_dispatch") | [.target_name, .status, .detail] | join("|")' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch-skip-switch.yaml -passes=obf-indirect-dispatch -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/indirect-dispatch-skip-switch.yaml -passes=obf-indirect-dispatch -S %s -o - | %opt -passes=verify -disable-output

define i32 @oversized_switch(i32 %x) {
entry:
  switch i32 %x, label %default [
    i32 0, label %ret
    i32 1, label %ret
    i32 2, label %ret
    i32 3, label %ret
    i32 4, label %ret
    i32 5, label %ret
    i32 6, label %ret
    i32 7, label %ret
    i32 8, label %ret
    i32 9, label %ret
    i32 10, label %ret
  ]

default:
  ret i32 0

ret:
  ret i32 %x
}

define i32 @small_switch(i32 %x) {
entry:
  switch i32 %x, label %default [
    i32 0, label %ret
    i32 1, label %ret
  ]

default:
  ret i32 0

ret:
  ret i32 42
}

define i32 @small_branch(i1 %cond) {
entry:
  br i1 %cond, label %left, label %right

left:
  ret i32 1

right:
  ret i32 2
}

; IR-LABEL: define i32 @oversized_switch(i32 %x)
; IR: switch i32 %x, label %default
; IR-NOT: indirectbr

; IR-LABEL: define i32 @small_switch(i32 %x)
; IR-NOT: switch i32 %x
; IR: indirectbr

; IR-LABEL: define i32 @small_branch(i1 %cond)
; IR-NOT: br i1 %cond
; IR: indirectbr

; REPORT: oversized_switch|skipped|no supported branch or switch sites
; REPORT-SAME: selected(branch_sites=0, switch_sites=0, shape=none)
; REPORT-SAME: skipped(max_switch_targets=1, non_integral_program_as=0, unsupported_function_shape=0)
; REPORT-SAME: first_oversized_switch_targets=12>3

; REPORT: small_switch|applied|1 site(s) selected
; REPORT-SAME: selected(branch_sites=0, switch_sites=1, shape=switch_only)

; REPORT: small_branch|applied|1 site(s) selected
; REPORT-SAME: selected(branch_sites=1, switch_sites=0, shape=branch_only)
