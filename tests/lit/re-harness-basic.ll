; RUN: %python %S/../../tools/obf-re-harness/score_vm_resistance.py --self-test --json-out %t.json --strict --fail-max-recovery-score 200
; RUN: %FileCheck %s --input-file=%t.json

; CHECK: "benchmark": "selftest"
; CHECK: "mapped_wrapper_count": 1
; CHECK: "physical_opcodes": [
; CHECK-NEXT: -3
; CHECK: "split_opcode_header_count": 1
; CHECK: "transformed_opcode_constants": []
; CHECK: "trap_oracle_indirect_count": 2
; CHECK: "wrapper_to_implementation": {
; CHECK-NEXT: "self_wrapper": "__obf_vm_i_self"
; CHECK: "schema_version": 1
; CHECK: "tool": "obf-re-harness"
