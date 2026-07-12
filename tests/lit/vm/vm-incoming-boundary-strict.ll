; Strict VM boundary must fail closed rather than silently leave an incoming
; site unvirtualized. This must hold both for the strong_vm level and for a
; plain `vm`-level function under a high-security profile (fortress/lab): the
; shared requires_strict_vm_boundary predicate closes the profile hole.
;
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-boundary-strict-strongvm.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRONGVM
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-boundary-strict-fortress.yaml -passes=obf-vm -disable-output %s 2>&1 | %FileCheck %s --check-prefix=FORTRESS

declare i32 @__gxx_personality_v0(...)

define i32 @vm_target(i32 %x) {
entry:
  %a = xor i32 %x, 4660
  %b = add nsw i32 %a, 85
  ret i32 %b
}

define i32 @caller_invoke(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  %r = invoke i32 @vm_target(i32 %x) to label %cont unwind label %lpad
cont:
  ret i32 %r
lpad:
  %e = landingpad { ptr, i32 } cleanup
  ret i32 -1
}

define i32 @main() {
entry:
  %r = call i32 @caller_invoke(i32 0)
  ret i32 %r
}

; STRONGVM: LLVM ERROR: vm strict boundary violation: function vm_target has an incoming invoke site
; FORTRESS: LLVM ERROR: vm strict boundary violation: function vm_target has an incoming invoke site
