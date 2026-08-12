; REQUIRES: system-linux-x86-64
; RUN: timeout 180 %python %S/../Inputs/re-harness-binary-fixtures.py --python %python --analyzer %S/../../../tools/obf-re-harness/score_binary_recovery.py --controller %S/../../../tools/obf-re-harness/verify_binary_recovery_controls.py --compiler %raw_clang --llvm-objdump %llvm_objdump --llvm-strip %llvm_strip --source %S/../Inputs/re-harness-binary-controls.c --work %t.controls | %FileCheck %s --check-prefix=SUMMARY
;
; SUMMARY: controls=5
; SUMMARY-NEXT: native_controls=not_vm_candidate
; SUMMARY-NEXT: positive_expectation_override=exact_interpreter_like
; SUMMARY-NEXT: positive_expectation_mismatch=partial_rejected
; SUMMARY-NEXT: positive_expectation_default=exact_vm_candidate_rejected
; SUMMARY-NEXT: positive_minimum=interpreter_like_or_vm_candidate
; SUMMARY-NEXT: positive_minimum_malformed=partial_rejected
; SUMMARY-NEXT: positive_minimum_duplicate=rejected
; SUMMARY-NEXT: positive_minimum_unmatched=rejected
; SUMMARY-NEXT: positive_expectation_minimum_conflict=rejected
; SUMMARY-NEXT: structural_invariance=pass
; SUMMARY-NEXT: score_gate=pass
; SUMMARY-NEXT: invalid_nonstrict=7
; SUMMARY-NEXT: invalid_strict=report_before_fail
; SUMMARY-NEXT: objdump_failure=report_before_fail
; SUMMARY-NEXT: binary_control_fixtures=pass

define void @dummy() {
entry:
  ret void
}
