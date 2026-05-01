; RUN: %python %S/../../tools/obf-re-harness/score_vm_resistance.py --self-test --json-out %t.json --strict --fail-max-recovery-score 200
; RUN: %FileCheck %s --input-file=%t.json

; CHECK: "benchmark": "selftest"
; CHECK: "handler_mapping_confidence": "trampoline"
; CHECK: "direct_success_to_handler_count": 0
; CHECK: "local_split_opcode_header_count": 0
; CHECK: "mapped_wrapper_count": 1
; CHECK: "nonlocal_split_fragment_count": 1
; CHECK: "nonlocal_split_opcode_header_count": 1
; CHECK: "split_opcode_header_count": 1
; CHECK: "success_to_trampoline_count": 2
; CHECK: "trampoline_to_handler_count": 2
; CHECK: "trap_oracle_indirect_count": 2
; CHECK: "opcode_recovery_confidence": "raw_physical"
; CHECK: "physical_opcodes": [
; CHECK-NEXT: -3
; CHECK: "predicate_locality_confidence": "non_local"
; CHECK: "transformed_opcode_constants": []
; CHECK: "wrapper_to_implementation": {
; CHECK-NEXT: "self_wrapper": "__obf_vm_i_self"
; CHECK: "schema_version": 1
; CHECK: "tool": "obf-re-harness"
