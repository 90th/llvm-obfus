; Incoming-callsite boundary classification (non-strict): ordinary calls are
; rewritten through the VM thunk, while invoke / musttail / operand-bundle sites
; are preserved pointing at the original-signature wrapper. `verify` proves no
; invalid IR is produced (the pre-fix code erased these terminators/bundle sites
; and produced malformed IR). Coverage runs both the isolated VM pass and the
; full safe pipeline (whose ordering differs), and executes every path.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes='obf-vm,verify' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes='obf-safe-pipeline,verify' -S %s -o - | %FileCheck %s --check-prefix=PIPE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes=obf-safe-pipeline -S %s -o %t.pipe
; RUN: %lli %t.pipe

define i32 @__gxx_personality_v0(...) {
  ret i32 0
}

define i32 @vm_target(i32 %x) {
entry:
  %a = xor i32 %x, 4660
  %b = add nsw i32 %a, 85
  ret i32 %b
}

define i32 @caller_ordinary(i32 %x) {
entry:
  %r = call i32 @vm_target(i32 %x)
  ret i32 %r
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

define i32 @caller_musttail(i32 %x) {
entry:
  %r = musttail call i32 @vm_target(i32 %x)
  ret i32 %r
}

define i32 @caller_bundle(i32 %x) {
entry:
  %r = call i32 @vm_target(i32 %x) [ "deopt"() ]
  ret i32 %r
}

define i32 @main() {
entry:
  %a = call i32 @caller_ordinary(i32 0)
  %b = call i32 @caller_invoke(i32 0)
  %c = call i32 @caller_musttail(i32 0)
  %d = call i32 @caller_bundle(i32 0)
  %ok_a = icmp eq i32 %a, 4745
  %ok_b = icmp eq i32 %b, 4745
  %ok_c = icmp eq i32 %c, 4745
  %ok_d = icmp eq i32 %d, 4745
  %ab = and i1 %ok_a, %ok_b
  %cd = and i1 %ok_c, %ok_d
  %all = and i1 %ab, %cd
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; Isolated VM pass: virtualization happened (VM implementation emitted) and the
; unsupported incoming sites are preserved on the original interface.
; CHECK-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK-DAG: invoke i32 @vm_target(i32
; CHECK-DAG: musttail call i32 @vm_target(i32
; CHECK-DAG: call i32 @vm_target(i32 {{[^)]*}}) [ "deopt"() ]

; Full safe pipeline: the preserved sites survive every downstream transform
; (cleanup renames internal artifacts, so only the preserved sites are checked).
; PIPE-DAG: invoke i32 @vm_target(i32
; PIPE-DAG: musttail call i32 @vm_target(i32
; PIPE-DAG: call i32 @vm_target(i32 {{[^)]*}}) [ "deopt"() ]
