; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-recursive-splitting.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_recursive_split_target' --implicit-check-not='__obf_vm_hs_recursive_split_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-recursive-splitting.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-recursive-splitting.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @recursive_split_target(i32 %x, i32 %y) {
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
  %v25 = add i32 %v24, %x
  %v26 = shl i32 %v25, 1
  %v27 = lshr i32 %v26, 3
  %v28 = xor i32 %v27, 8738
  %v29 = add i32 %v28, %y
  %v30 = mul i32 %v29, 9
  %v31 = sub i32 %v30, 41
  %v32 = and i32 %v31, 524287
  %v33 = or i32 %v32, 65
  %v34 = xor i32 %v33, %x
  %v35 = add i32 %v34, 123
  %v36 = lshr i32 %v35, 2
  %v37 = mul i32 %v36, 11
  %v38 = add i32 %v37, %y
  %v39 = xor i32 %v38, 17476
  %v40 = sub i32 %v39, 59
  %v41 = and i32 %v40, 1048575
  %v42 = or i32 %v41, 129
  %v43 = shl i32 %v42, 1
  %v44 = lshr i32 %v43, 2
  %v45 = xor i32 %v44, %y
  %v46 = add i32 %v45, %x
  %v47 = mul i32 %v46, 13
  %v48 = sub i32 %v47, 71
  %v49 = and i32 %v48, 2097151
  %v50 = or i32 %v49, 257
  %v51 = xor i32 %v50, 34952
  %v52 = add i32 %v51, %y
  %v53 = shl i32 %v52, 2
  %v54 = lshr i32 %v53, 1
  %v55 = sub i32 %v54, %x
  %v56 = mul i32 %v55, 3
  %v57 = xor i32 %v56, 69904
  %v58 = and i32 %v57, 4194303
  %v59 = or i32 %v58, 513
  %v60 = add i32 %v59, 181
  %v61 = xor i32 %v60, %y
  %v62 = add i32 %v61, %x
  %v63 = mul i32 %v62, 5
  %v64 = sub i32 %v63, 89
  %v65 = and i32 %v64, 8388607
  %v66 = or i32 %v65, 1025
  %v67 = shl i32 %v66, 1
  %v68 = lshr i32 %v67, 4
  %v69 = xor i32 %v68, 139808
  %v70 = add i32 %v69, %y
  %v71 = mul i32 %v70, 7
  %v72 = sub i32 %v71, %x
  %v73 = and i32 %v72, 16777215
  %v74 = or i32 %v73, 2049
  %v75 = xor i32 %v74, 279616
  %v76 = add i32 %v75, 211
  %v77 = shl i32 %v76, 1
  %v78 = lshr i32 %v77, 3
  %v79 = add i32 %v78, %x
  %v80 = xor i32 %v79, %y
  %v81 = mul i32 %v80, 9
  %v82 = sub i32 %v81, 107
  %v83 = and i32 %v82, 33554431
  %v84 = or i32 %v83, 4097
  %v85 = xor i32 %v84, 559232
  %v86 = add i32 %v85, %y
  %v87 = mul i32 %v86, 11
  %v88 = sub i32 %v87, %x
  %v89 = and i32 %v88, 67108863
  %v90 = or i32 %v89, 8193
  %v91 = shl i32 %v90, 1
  %v92 = lshr i32 %v91, 2
  %v93 = xor i32 %v92, 1118464
  %v94 = add i32 %v93, %x
  %v95 = sub i32 %v94, %y
  %v96 = mul i32 %v95, 13
  %zero = xor i32 %v96, %v96
  ret i32 %zero
}

define i32 @main() {
entry:
  %ret = call i32 @recursive_split_target(i32 29, i32 17)
  ret i32 %ret
}

; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}_s{{[0-9]+}}_h0 = private unnamed_addr constant
; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM: %vm.island.root.route{{[0-9]*}} = load i32, ptr %vm.island.state.island
; VM: switch i32 %vm.island.root.route{{[0-9]*}}
; VM-NOT: @__obf_vm_hs_
; VM-LABEL: define internal i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM: %vm.island.subroute = load i32, ptr %vm.island.state.dispatch
; VM: switch i32 %vm.island.subroute
; VM: call i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
; VM-LABEL: define internal i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.subhelper.state)
; VM: %vm.island.subroute.dispatch = load i32, ptr %vm.island.state.dispatch
; VM: switch i32 %vm.island.subroute.dispatch
; VM: vm.island.subhelper.decode
; VM: obf.vm.bc
; VM: store i32 {{[^,]+}}, ptr %vm.island.state.dispatch
; VM: store i32 {{[0-9]+}}, ptr %vm.island.state.island
; VM: ret i32 -3
; VM-DAG: define internal i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.subhelper.state)
; VM-DAG: define internal i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.subhelper.state)
; VM-DAG: "vm.island.helper.split"
; VM-DAG: "vm.island.helper.large"
; VM-DAG: "vm.island.leaf"
; VM-DAG: "vm.island.leaf.route"
; VM-DAG: "vm.island.leaf.table.shard"
; VM-DAG: "vm.island.recursive.split"
; VM-DAG: "vm.island.recursive.depth.1"
; VM-DAG: "vm.island.subhelper"
; VM-DAG: "vm.island.subroute"
; VM-DAG: "vm.island.subtable.shard"
; VM-DAG: "vm.island.root.small"
; VM-NOT: obf.vm.dispatch.index.bank
