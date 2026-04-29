; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-root-reduction.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_root_reduction_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-root-reduction.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-root-reduction.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @root_reduction_target(i32 %x, i32 %y) {
entry:
  %v01 = add i32 %x, 7
  %v02 = xor i32 %v01, %y
  %v03 = mul i32 %v02, 3
  %v04 = sub i32 %v03, 9
  %v05 = or i32 %v04, 33
  %v06 = and i32 %v05, 4095
  %v07 = shl i32 %v06, 2
  %v08 = lshr i32 %v07, 1
  %v09 = add i32 %v08, %x
  %v10 = xor i32 %v09, 170
  %v11 = sub i32 %v10, %y
  %v12 = mul i32 %v11, 5
  %v13 = add i32 %v12, 19
  %v14 = xor i32 %v13, 85
  %v15 = and i32 %v14, 2047
  %v16 = or i32 %v15, 64
  %v17 = sub i32 %v16, 31
  %v18 = add i32 %v17, %y
  %v19 = xor i32 %v18, %x
  %v20 = mul i32 %v19, 7
  %v21 = lshr i32 %v20, 3
  %v22 = add i32 %v21, 101
  %v23 = xor i32 %v22, %y
  %v24 = sub i32 %v23, 29
  %v25 = add i32 %v24, %x
  %v26 = mul i32 %v25, 3
  %v27 = xor i32 %v26, 12345
  %v28 = and i32 %v27, 65535
  %v29 = or i32 %v28, 256
  %v30 = sub i32 %v29, 77
  %v31 = lshr i32 %v30, 2
  %v32 = add i32 %v31, %y
  %v33 = xor i32 %v32, %x
  %v34 = mul i32 %v33, 9
  %v35 = and i32 %v34, 32767
  %v36 = add i32 %v35, 42
  ret i32 %v36
}

define i32 @main() {
entry:
  %ret = call i32 @root_reduction_target(i32 13, i32 6)
  %ok = icmp eq i32 %ret, 1591
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}_s0 = private unnamed_addr constant
; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}_s1 = private unnamed_addr constant
; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}_s2 = private unnamed_addr constant
; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM: %vm.island.root.finalize{{[0-9]*}} = load i32, ptr %vm.island.state.ret
; VM: %vm.island.root.route{{[0-9]*}} = load i32, ptr %vm.island.state.island
; VM: switch i32 %vm.island.root.route{{[0-9]*}}
; VM-NOT: obf.vm.dispatch.index.bank
; VM: call i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM-LABEL: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM: %vm.island.helper.dispatch = load i32, ptr %vm.island.state.dispatch
; VM: switch i32 %vm.island.helper.dispatch
; VM: vm.island.helper.decode
; VM-DAG: "vm.island.count.3"
; VM-DAG: "vm.island.helper.decode"
; VM-DAG: "vm.island.helper.dispatch"
; VM-DAG: "vm.island.helper.table"
; VM-DAG: "vm.island.leaf"
; VM-DAG: "vm.island.leaf.route"
; VM-DAG: "vm.island.leaf.table.shard"
; VM-DAG: "vm.island.next_island"
; VM-DAG: "vm.island.root.finalize"
; VM-DAG: "vm.island.root.route"
; VM-DAG: "vm.island.root.small"
; VM-DAG: "vm.island.subtable.shard"
; VM-DAG: "vm.island.table.shard"
