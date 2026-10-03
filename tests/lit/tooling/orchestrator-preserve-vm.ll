; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-preserve-vm.yaml -passes=obf-feature-report -disable-output %s > %t.predictions.json
; RUN: %FileCheck %s --check-prefix=POLICY < %t.predictions.json
; RUN: env OBF_COVERAGE_REPORT=%t.coverage.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/orchestrator-preserve-vm.yaml -passes=obf-safe-pipeline,verify -S %s -o %t.ll
; RUN: %FileCheck %s --check-prefix=BINDING < %t.ll
; RUN: %lli %t.ll
; RUN: %python -c "import json,sys; d=json.load(open(sys.argv[1])); original={x['name']:x['policy'] for x in json.load(open(sys.argv[2]))['functions']}; p=[x for x in d['requested_policy'] if x['owner']=='vm_relay']; s=[x for x in p if x['phase']=='selected']; e=[x for x in p if x['phase']=='effective']; assert len(s)==len(e)==1; assert s[0]['policy']['level']=='vm' and s[0]['policy']['source']=='explicit_override'; assert e[0]['policy']==original['vm_relay']; assert e[0]['policy']['allow_vm'] and e[0]['policy']['allow_instruction_substitution']; assert 'protected_core' in e[0]['policy']['detail']; assert all(r['owner'] in ('','protected_core','vm_relay','restricted_vm_relay','main') for r in d['roles'] if r['role']!='source'); assert any(x['mechanism']=='vm' and x['owner']=='vm_relay' and x['status']=='emitted' for x in d['emission'])" %t.coverage.json %t.predictions.json
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
