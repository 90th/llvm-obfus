; REQUIRES: system-linux-x86-64
; RUN: printf 'int main(void) { return 0; }\n' | %raw_clang -x c - -o %t.normal
; RUN: %llvm_strip --strip-all %t.normal
; RUN: %python %S/../../../tools/obf-re-harness/score_binary_recovery.py --binary %t.normal --llvm-objdump %llvm_objdump --json-out %t.json --strict
; RUN: %FileCheck %s --input-file=%t.json

; CHECK-DAG: "analysis_boundary": "binary-only"
; CHECK-DAG: "report_kind": "binary_vm_recovery"
; CHECK-DAG: "schema_version": 1
; CHECK-DAG: "tool": "obf-re-harness-binary"
; CHECK-DAG: "classification": "inconclusive"
; CHECK-DAG: "semantic_recovery": "unavailable"
