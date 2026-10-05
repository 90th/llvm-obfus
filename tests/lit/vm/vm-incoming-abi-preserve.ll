; Ordinary vm must preserve ABI-incompatible incoming sites without dropping
; whole-function VM emission. Both the isolated pass and the full safe pipeline
; verify all ten inputs and all transformed outputs. The helper checks compiler
; admission/emission events and requires VM eligibility at the requested vm level.
;
; Too-few, parameter-type, return-type, ccc-to-fastcc, and extension-attribute
; mismatches have undefined calling semantics despite valid input IR. They have
; no main and are never executed. The ccc surplus-argument and variadic-shape-only
; calls are safe executable preservation controls, alongside matching ccc,
; fastcc, and signext/zeroext controls. Each main checks two precise returns and
; two precise cumulative memory effects, including negative extension results.
;
; RUN: rm -rf "%t.vm" "%t.safe"
; RUN: %python "%S/../Inputs/vm_incoming_abi.py" --cases "%S/../Inputs/vm-incoming-abi-cases.ir" --work "%t.vm" --plugin %obf_plugin --pipeline obf-vm -- %opt
; RUN: %lli "%t.vm/surplus/input.ll"
; RUN: %lli "%t.vm/variadic_shape/input.ll"
; RUN: %lli "%t.vm/matching_c/input.ll"
; RUN: %lli "%t.vm/matching_fast/input.ll"
; RUN: %lli "%t.vm/matching_extensions/input.ll"
; RUN: %lli "%t.vm/surplus/output.ll"
; RUN: %lli "%t.vm/variadic_shape/output.ll"
; RUN: %lli "%t.vm/matching_c/output.ll"
; RUN: %lli "%t.vm/matching_fast/output.ll"
; RUN: %lli "%t.vm/matching_extensions/output.ll"
; RUN: %python "%S/../Inputs/vm_incoming_abi.py" --cases "%S/../Inputs/vm-incoming-abi-cases.ir" --work "%t.safe" --plugin %obf_plugin --pipeline obf-safe-pipeline -- %opt
; RUN: %lli "%t.safe/surplus/output.ll"
; RUN: %lli "%t.safe/variadic_shape/output.ll"
; RUN: %lli "%t.safe/matching_c/output.ll"
; RUN: %lli "%t.safe/matching_fast/output.ll"
; RUN: %lli "%t.safe/matching_extensions/output.ll"
