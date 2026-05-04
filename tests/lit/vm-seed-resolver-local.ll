; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-seed-resolver-local.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=STRONG --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_seedcase_strong_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-seed-resolver-local.yaml -passes=obf-vm -S %s -o %t.strong
; RUN: %lli %t.strong
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-seed-resolver-local-mixed.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=MIXED --implicit-check-not='@__obf_vm_seedcase_strong_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-seed-resolver-local-mixed.yaml -passes=obf-vm -S %s -o %t.mixed
; RUN: %lli %t.mixed

define i32 @strong_target(i32 %x) {
entry:
  %xor = xor i32 %x, 42
  %sum = add i32 %xor, 7
  ret i32 %sum
}

define i32 @normal_target(i32 %x) {
entry:
  %sum = add i32 %x, 11
  %xor = xor i32 %sum, 3
  ret i32 %xor
}

define i32 @main() {
entry:
  %strong = call i32 @strong_target(i32 5)
  %normal = call i32 @normal_target(i32 9)
  %strong.ok = icmp eq i32 %strong, 54
  %normal.ok = icmp eq i32 %normal, 23
  %ok = and i1 %strong.ok, %normal.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; STRONG-LABEL: define i32 @strong_target(i32 %x)
; STRONG: ptrtoint (ptr @[[STRONGTHUNK:__obf_vm_e_[A-Za-z0-9_]+]] to i{{[0-9]+}})
; STRONG: define internal i32 @[[STRONGTHUNK]](i32 {{.*}}, i64 %obf.hidden_token){{.*}}

; MIXED: ptrtoint (ptr @[[MIXEDSTRONG_THUNK:__obf_vm_e_[A-Za-z0-9_]+]] to i{{[0-9]+}})
; MIXED: call i{{[0-9]+}} @__obf_vm_seed_resolve
; MIXED-DAG: define internal i32 @[[MIXEDSTRONG_THUNK]](i32 {{.*}}, i64 %obf.hidden_token){{.*}}
; MIXED-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token){{.*}}
; MIXED-DAG: define private i{{[0-9]+}} @__obf_vm_seed_resolve
; MIXED-DAG: define private i{{[0-9]+}} @__obf_vm_c_{{[A-Za-z0-9_]+}}
