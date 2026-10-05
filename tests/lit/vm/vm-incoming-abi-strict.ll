; Strict incoming ABI classification must fail closed before VM binding or
; emission. Run all seven mismatches under strong_vm/standard, vm/fortress,
; and vm/lab, through both obf-vm and obf-safe-pipeline (42 rejections).
; Matching C, fastcc, and extension-attribute calls remain VM-eligible under
; every policy/pipeline (18 verified VM emissions).
;
; The helper verifies all ten standalone inputs before any transform, checks
; the deliberate strict-boundary compiler rejection category and semantic
; coverage ledger, and never executes incompatible calls. Every invocation
; retains isolated evidence under this test's unique temporary root; the shared
; reader is import-safe.
;
; RUN: %python "%S/../Inputs/vm_incoming_abi_strict.py" --cases "%S/../Inputs/vm-incoming-abi-cases.ir" --plugin %obf_plugin --work "%t.work" -- %opt
