; Check non-strict incoming-callsite behavior for ordinary calls, invoke,
; musttail, and operand bundles. All callers must return the expected value.
; Both the isolated VM pass and the full safe pipeline must produce valid IR.
; The coverage report must retain the incoming-callsite restrictions.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes='obf-vm,verify' -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes='obf-safe-pipeline,verify' -S %s -o %t.pipe
; RUN: %lli %t.pipe
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-incoming-callsite-boundary.yaml -passes='obf-coverage-start,obf-vm,obf-coverage-report' -disable-output %s > %t.coverage.json
; RUN: %python %S/../Inputs/report_contract.py incoming %t.coverage.json

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

