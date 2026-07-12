; A target carrying an ABI-affecting parameter attribute (here byval) cannot be
; safely virtualized: cloning appends a hidden token and the callsite is
; forwarded through an indirect thunk. Non-strict: the boundary rejects it,
; leaving the function untouched and the module valid. Strict (strong_vm):
; fail closed.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-abi-attr.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --implicit-check-not='@__obf_vm_'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-abi-attr-strongvm.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRICT

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
