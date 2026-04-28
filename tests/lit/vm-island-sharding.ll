; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-sharding.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_shard_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-sharding.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-sharding.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @shard_target(i32 %x, i32 %y) {
entry:
  %v01 = add i32 %x, 3
  %v02 = xor i32 %v01, %y
  %v03 = mul i32 %v02, 5
  %v04 = sub i32 %v03, 7
  %v05 = or i32 %v04, 17
  %v06 = and i32 %v05, 1023
  %v07 = shl i32 %v06, 1
  %v08 = lshr i32 %v07, 2
  %v09 = add i32 %v08, 13
  %v10 = xor i32 %v09, 85
  %v11 = sub i32 %v10, %x
  %v12 = mul i32 %v11, 3
  %v13 = add i32 %v12, %y
  %v14 = xor i32 %v13, 170
  %v15 = and i32 %v14, 2047
  %v16 = or i32 %v15, 32
  %v17 = sub i32 %v16, 11
  %v18 = add i32 %v17, 19
  %v19 = xor i32 %v18, 51
  %v20 = mul i32 %v19, 7
  %v21 = lshr i32 %v20, 3
  %v22 = add i32 %v21, 101
  %v23 = xor i32 %v22, %y
  %v24 = sub i32 %v23, 29
  %v25 = add i32 %v24, %x
  ret i32 %v25
}

define i32 @main() {
entry:
  %ret = call i32 @shard_target(i32 12, i32 9)
  %ok = icmp eq i32 %ret, 174
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-LABEL: define i32 @shard_target(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM-DAG: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM-DAG: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM-DAG: vm.island.topology.helper_shards
; VM-DAG: vm.island.count.3
; VM-DAG: "vm.island.entry"
; VM-DAG: "vm.island.helper"
; VM-DAG: "vm.island.route"
; VM-DAG: "vm.island.state"
