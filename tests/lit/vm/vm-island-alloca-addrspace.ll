; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-dispatcher-islands.yaml -passes=obf-vm,verify -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='addrspacecast' --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_island_target' --implicit-check-not='__obf_vm_hs_island_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-dispatcher-islands.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-dispatcher-islands.yaml -passes=obf-safe-pipeline -disable-output %s

; Regression: with A1 alloca pointers, island helpers and recursive subhelpers
; must carry the actual state pointer address space through their signatures/calls.

target datalayout = "e-p:64:64-p1:64:64-A1"

define i32 @island_target(i32 %x, i32 %y) {
entry:
  %v01 = add i32 %x, 11
  %v02 = xor i32 %v01, %y
  %v03 = mul i32 %v02, 3
  %v04 = sub i32 %v03, 17
  %v05 = and i32 %v04, 65535
  %v06 = or i32 %v05, 7
  %v07 = shl i32 %v06, 1
  %v08 = lshr i32 %v07, 2
  %v09 = add i32 %v08, %x
  %v10 = xor i32 %v09, 85
  %v11 = add i32 %v10, %y
  %v12 = mul i32 %v11, 5
  %v13 = sub i32 %v12, 23
  %v14 = and i32 %v13, 131071
  %v15 = or i32 %v14, 19
  %v16 = shl i32 %v15, 2
  %v17 = lshr i32 %v16, 1
  %v18 = xor i32 %v17, %x
  %v19 = add i32 %v18, 97
  %v20 = sub i32 %v19, %y
  %v21 = mul i32 %v20, 7
  %v22 = xor i32 %v21, 4369
  %v23 = and i32 %v22, 262143
  %v24 = or i32 %v23, 33
  %v25 = xor i32 %v24, %y
  ret i32 %v25
}

define i32 @main() {
entry:
  %slot = alloca i32, align 4, addrspace(1)
  store i32 29, ptr addrspace(1) %slot, align 4
  %x0 = load i32, ptr addrspace(1) %slot, align 4
  %ret0 = call i32 @island_target(i32 %x0, i32 17)
  store i32 8, ptr addrspace(1) %slot, align 4
  %x1 = load i32, ptr addrspace(1) %slot, align 4
  %ret1 = call i32 @island_target(i32 %x1, i32 5)
  %ok0 = icmp eq i32 %ret0, 1532
  %ok1 = icmp eq i32 %ret1, 12914
  %ok = and i1 %ok0, %ok1
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-LABEL: define i32 @island_target(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state)
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state)
; VM-DAG: define internal {{.*}} @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state)
; VM-DAG: define internal {{.*}} @__obf_vm_hd_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state)
; VM-DAG: define internal {{.*}} @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.subhelper.state)
; VM-DAG: call i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state{{[0-9]*}})
; VM-DAG: call i32 @__obf_vm_hd_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state{{[0-9]*}})
; VM-DAG: call i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr addrspace(1) %vm.island.state{{[0-9]*}})
; VM-DAG: vm.island.topology.helper_shards
; VM-DAG: vm.island.count.3
; VM-DAG: "vm.island.entry"
; VM-DAG: "vm.island.helper"
; VM-DAG: "vm.island.route"
; VM-DAG: "vm.island.state"
; VM-DAG: "vm.island.helper.split"
; VM-DAG: "vm.island.subhelper"
; VM-DAG: "vm.island.subroute"
