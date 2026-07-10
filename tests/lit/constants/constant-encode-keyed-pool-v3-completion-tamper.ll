; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/constant-encode-keyed-pool.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %python %S/../Inputs/tamper_string_auth_ir.py %t auto clear-completion-before-second-call
; RUN: %python %S/../Inputs/assert_trap_within.py %lli %t

define i32 @repeated() {
entry:
  %a = add i32 5, 31337
  %b = xor i32 %a, 31337
  %c = add i32 %b, 31337
  %ok = icmp eq i32 %c, 31344
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %value = call i32 @repeated()
  ret i32 %value
}

; IR: @__obf_const_state_ref_
; IR: @__obf_const_topology_
; IR: define internal ptr @__obf_const_pool_decode_
; IR: call ptr @rt_core_cpd3(
