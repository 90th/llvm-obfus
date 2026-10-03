; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-preserve-vm.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=POLICY
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-preserve-vm.yaml -passes=obf-safe-pipeline,verify -S %s -o %t.ll
; RUN: %FileCheck %s --check-prefix=BINDING < %t.ll
; RUN: %lli %t.ll
;
; Adding classical caller protection must not replace a selected VM obligation.
; POLICY: "name":"vm_relay"{{[^}]*}}"allow_instruction_substitution":true{{[^}]*}}"allow_vm":true{{[^}]*}}"level":"vm"
; POLICY: "name":"restricted_vm_relay"{{[^}]*}}"allow_vm":false{{[^}]*}}"level":"vm"
; BINDING: define internal i32 @{{[^ (]+}}(i32 {{[^,]+}}, ptr {{[^,]+}}, i64

@effect = internal global i32 0

define i32 @protected_core(i32 %value) noinline {
entry:
  %scaled = mul i32 %value, 3
  %result = add i32 %scaled, 1
  ret i32 %result
}

define i32 @vm_relay(i32 %value, ptr %destination) {
entry:
  %protected = call i32 @protected_core(i32 %value)
  %result = add i32 %protected, 5
  store i32 %result, ptr %destination
  ret i32 %result
}

define i32 @restricted_vm_relay(i32 %value) {
entry:
  call void asm sideeffect "", ""()
  %result = call i32 @protected_core(i32 %value)
  ret i32 %result
}

define i32 @main() {
entry:
  %result = call i32 @vm_relay(i32 3, ptr @effect)
  %observed = load i32, ptr @effect
  %return_ok = icmp eq i32 %result, 15
  %effect_ok = icmp eq i32 %observed, 15
  %ok = and i1 %return_ok, %effect_ok
  %status = select i1 %ok, i32 0, i32 1
  ret i32 %status
}
