; A target carrying an ABI-affecting parameter attribute (here byval) cannot be
; safely virtualized: cloning appends a hidden token and the callsite is
; forwarded through an indirect thunk. Non-strict: the boundary rejects it,
; leaving the function untouched and the module valid. Strict (strong_vm):
; fail closed.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-abi-attr.yaml -passes=obf-feature-report -disable-output %s > %t.predictions.json
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-abi-attr.yaml -passes='obf-coverage-start,obf-vm,obf-coverage-report,verify' -S %s -o %t.ll > %t.coverage.json
; RUN: %FileCheck %s --implicit-check-not='@__obf_vm_' < %t.ll
; RUN: %python %S/../Inputs/report_contract.py abi %t.coverage.json --predictions %t.predictions.json --ir %t.ll
; RUN: env OBF_COVERAGE_REPORT=%t.strict.json not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-abi-attr-strongvm.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRICT
; RUN: %python %S/../Inputs/report_contract.py abi %t.strict.json --strict

define i32 @abi_target(i32 %x, ptr byval(i32) %p) {
entry:
  %a = xor i32 %x, 4660
  %b = add nsw i32 %a, 85
  ret i32 %b
}

define i32 @caller(i32 %x, ptr %p) {
entry:
  %r = call i32 @abi_target(i32 %x, ptr byval(i32) %p)
  ret i32 %r
}

; CHECK: define i32 @abi_target(i32 %x, ptr byval(i32) %p)
; STRICT: LLVM ERROR: vm strict boundary violation: function abi_target cannot be virtualized safely
