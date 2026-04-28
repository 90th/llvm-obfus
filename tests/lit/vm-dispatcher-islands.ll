; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-islands.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_island_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-islands.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-islands.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @island_target(i32 %x, i32 %y, ptr %p) {
entry:
  %a0 = add i32 %x, 11
  %a1 = xor i32 %a0, %y
  %a2 = mul i32 %a1, 3
  %a3 = sub i32 %a2, 7
  %old = load i32, ptr %p, align 4
  %a4 = add i32 %a3, %old
  %cmp = icmp sgt i32 %a4, 40
  br i1 %cmp, label %then, label %else

then:
  %t0 = xor i32 %a4, 85
  %t1 = sub i32 %t0, 64
  store i32 %t1, ptr %p, align 4
  br label %join

else:
  %e0 = or i32 %a4, 19
  %e1 = sub i32 %e0, 5
  store i32 %e1, ptr %p, align 4
  br label %join

join:
  %phi = phi i32 [ %t1, %then ], [ %e1, %else ]
  %tag = and i32 %phi, 3
  switch i32 %tag, label %default [
    i32 0, label %case0
    i32 1, label %case1
    i32 2, label %case2
  ]

case0:
  %c0 = add i32 %phi, 101
  br label %exit

case1:
  %c1 = xor i32 %phi, 202
  br label %exit

case2:
  %c2 = add i32 %phi, 182
  br label %exit

default:
  %cd = add i32 %phi, %tag
  br label %exit

exit:
  %ret = phi i32 [ %c0, %case0 ], [ %c1, %case1 ], [ %c2, %case2 ], [ %cd, %default ]
  ret i32 %ret
}

define i32 @main() {
entry:
  %slot = alloca i32, align 4
  store i32 4, ptr %slot, align 4
  %ret = call i32 @island_target(i32 8, i32 5, ptr %slot)
  %stored = load i32, ptr %slot, align 4
  %ret.ok = icmp eq i32 %ret, 224
  %stored.ok = icmp eq i32 %stored, 42
  %ok = and i1 %ret.ok, %stored.ok
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-LABEL: define i32 @island_target(i32 %x, i32 %y, ptr %p)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, ptr %p, i64 %{{[^)]+}})
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, ptr %p, i64 %obf.hidden_token)
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}
; VM-DAG: vm.island.topology.helper_shards
; VM-DAG: vm.island.count.3
; VM-DAG: "vm.island.entry"
; VM-DAG: "vm.island.helper"
; VM-DAG: "vm.island.route"
; VM-DAG: "vm.island.state"
