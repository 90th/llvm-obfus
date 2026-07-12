; inalloca is the concretely verifier-invalid F3 case: cloning appends a hidden
; i64 token, which would push the inalloca parameter out of last position and
; make the clone reject in the verifier. The boundary rejects such a target
; before cloning (non-strict: skipped, module stays valid under `verify`;
; strict strong_vm or high-security profile: fail closed).
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-inalloca.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s --implicit-check-not='@__obf_vm_'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-inalloca-strongvm.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRONGVM
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-boundary-inalloca-fortress.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=FORTRESS

%argpack = type { i32 }

define i32 @inalloca_target(ptr inalloca(%argpack) %p) {
entry:
  %f = getelementptr inbounds %argpack, ptr %p, i32 0, i32 0
  %v = load i32, ptr %f, align 4
  %r = add i32 %v, 85
  ret i32 %r
}

define i32 @caller() {
entry:
  %args = alloca inalloca %argpack, align 4
  %f = getelementptr inbounds %argpack, ptr %args, i32 0, i32 0
  store i32 4660, ptr %f, align 4
  %r = call i32 @inalloca_target(ptr inalloca(%argpack) %args)
  ret i32 %r
}

; CHECK: define i32 @inalloca_target(ptr inalloca(%argpack) %p)
; STRONGVM: LLVM ERROR: vm strict boundary violation: function inalloca_target cannot be virtualized safely
; FORTRESS: LLVM ERROR: vm strict boundary violation: function inalloca_target cannot be virtualized safely
