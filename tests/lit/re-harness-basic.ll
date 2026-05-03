; RUN: %python %S/../../tools/obf-re-harness/score_vm_resistance.py --self-test --json-out %t.json --strict --fail-max-recovery-score 200
; RUN: %FileCheck %s --input-file=%t.json

; CHECK: "benchmark": "selftest"
; CHECK-DAG: "bytecode_anchor_count": 1
; CHECK-DAG: "bytecode_shard_count": 1
; CHECK-DAG: "bytecode_decoy_count": 0
; CHECK-DAG: "bytecode_recovery_confidence": "concentrated"
; CHECK-DAG: "data_mapping_confidence": "concentrated"
; CHECK-DAG: "handler_mapping_confidence": "trampoline"
; CHECK-DAG: "direct_callsite_mapping_count": 0
; CHECK-DAG: "direct_success_to_handler_count": 0
; CHECK-DAG: "direct_wrapper_mapping_count": 0
; CHECK-DAG: "entry_thunk_count": 1
; CHECK-DAG: "entry_thunk_shape_counts": {
; CHECK-DAG: "direct": 1
; CHECK-DAG: "indirect_wrapper_mapping_count": 0
; CHECK-DAG: "local_split_opcode_header_count": 0
; CHECK-DAG: "mapped_wrapper_count": 1
; CHECK-DAG: "nonlocal_split_fragment_count": 1
; CHECK-DAG: "nonlocal_split_opcode_header_count": 1
; CHECK-DAG: "polymorphic_thunked_wrapper_mapping_count": 0
; CHECK-DAG: "shared_suffix_correlation_count": 2
; CHECK-DAG: "split_opcode_header_count": 1
; CHECK-DAG: "success_to_trampoline_count": 2
; CHECK-DAG: "tag_correlated_wrapper_mapping_count": 0
; CHECK-DAG: "thunked_callsite_mapping_count": 0
; CHECK-DAG: "thunked_wrapper_mapping_count": 1
; CHECK-DAG: "trampoline_to_handler_count": 2
; CHECK-DAG: "trap_oracle_indirect_count": 2
; CHECK-DAG: "opcode_recovery_confidence": "raw_physical"
; CHECK-DAG: "physical_opcodes": [
; CHECK-DAG: -3
; CHECK-DAG: "predicate_locality_confidence": "non_local"
; CHECK-DAG: "transformed_opcode_constants": []
; CHECK-DAG: "wrapper_mapping_confidence": "thunked"
; CHECK-DAG: "wrapper_to_implementation": {
; CHECK-DAG: "self_wrapper": "__obf_vm_i_self"
; CHECK-DAG: "schema_version": 1
; CHECK-DAG: "tool": "obf-re-harness"
