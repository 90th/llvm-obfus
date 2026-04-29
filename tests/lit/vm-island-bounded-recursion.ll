; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-bounded-recursion.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_bounded_recursion_target' --implicit-check-not='__obf_vm_hs_bounded_recursion_target'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-bounded-recursion.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-island-bounded-recursion.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @bounded_recursion_target(i32 %a, i32 %b, ptr %out) {
entry:
  %v00 = add i32 %a, 5
  %v01 = xor i32 %v00, %b
  %v02 = mul i32 %v01, 3
  %v03 = sub i32 %v02, 11
  %v04 = and i32 %v03, 65535
  %v05 = or i32 %v04, 17
  %v06 = shl i32 %v05, 1
  %v07 = lshr i32 %v06, 2
  %v08 = add i32 %v07, %a
  %v09 = xor i32 %v08, 91
  %v10 = add i32 %v09, %b
  %v11 = mul i32 %v10, 5
  %v12 = sub i32 %v11, 19
  %v13 = and i32 %v12, 131071
  %v14 = or i32 %v13, 33
  %v15 = shl i32 %v14, 2
  %v16 = lshr i32 %v15, 1
  %v17 = xor i32 %v16, %a
  %v18 = add i32 %v17, 101
  %v19 = sub i32 %v18, %b
  %v20 = mul i32 %v19, 7
  %v21 = xor i32 %v20, 4369
  %v22 = and i32 %v21, 262143
  %v23 = or i32 %v22, 65
  %v24 = add i32 %v23, %a
  %v25 = shl i32 %v24, 1
  %v26 = lshr i32 %v25, 3
  %v27 = xor i32 %v26, 8738
  %v28 = add i32 %v27, %b
  %v29 = mul i32 %v28, 9
  %v30 = sub i32 %v29, 41
  %v31 = and i32 %v30, 524287
  %v32 = or i32 %v31, 129
  %v33 = xor i32 %v32, %a
  %v34 = add i32 %v33, 123
  %v35 = lshr i32 %v34, 2
  %v36 = mul i32 %v35, 11
  %v37 = add i32 %v36, %b
  %v38 = xor i32 %v37, 17476
  %v39 = sub i32 %v38, 59
  %v40 = and i32 %v39, 1048575
  %v41 = or i32 %v40, 257
  %v42 = shl i32 %v41, 1
  %v43 = lshr i32 %v42, 2
  %v44 = xor i32 %v43, %b
  %v45 = add i32 %v44, %a
  %v46 = mul i32 %v45, 13
  %v47 = sub i32 %v46, 71
  %v48 = and i32 %v47, 2097151
  %v49 = or i32 %v48, 513
  %v50 = xor i32 %v49, 34952
  %v51 = add i32 %v50, %b
  %v52 = shl i32 %v51, 2
  %v53 = lshr i32 %v52, 1
  %v54 = sub i32 %v53, %a
  %v55 = mul i32 %v54, 3
  %v56 = xor i32 %v55, 69904
  %v57 = and i32 %v56, 4194303
  %v58 = or i32 %v57, 1025
  %v59 = add i32 %v58, 181
  %v60 = xor i32 %v59, %b
  %v61 = add i32 %v60, %a
  %v62 = mul i32 %v61, 5
  %v63 = sub i32 %v62, 89
  %v64 = and i32 %v63, 8388607
  %v65 = or i32 %v64, 2049
  %v66 = shl i32 %v65, 1
  %v67 = lshr i32 %v66, 4
  %v68 = xor i32 %v67, 139808
  %v69 = add i32 %v68, %b
  %v70 = mul i32 %v69, 7
  %v71 = sub i32 %v70, %a
  %v72 = and i32 %v71, 16777215
  %v73 = or i32 %v72, 4097
  %v74 = xor i32 %v73, 279616
  %v75 = add i32 %v74, 211
  %v76 = shl i32 %v75, 1
  %v77 = lshr i32 %v76, 3
  %v78 = add i32 %v77, %a
  %v79 = xor i32 %v78, %b
  %v80 = mul i32 %v79, 9
  %v81 = sub i32 %v80, 107
  %v82 = and i32 %v81, 33554431
  %v83 = or i32 %v82, 8193
  %v84 = xor i32 %v83, 559232
  %v85 = add i32 %v84, %b
  %v86 = mul i32 %v85, 11
  %v87 = sub i32 %v86, %a
  %v88 = and i32 %v87, 67108863
  %v89 = or i32 %v88, 16385
  %tag = and i32 %v89, 3
  switch i32 %tag, label %case_default [
    i32 0, label %case0
    i32 1, label %case1
    i32 2, label %case2
  ]

case0:
  %c0 = add i32 %v89, 19
  store i32 %c0, ptr %out, align 4
  br label %done

case1:
  %c1 = xor i32 %v89, 51
  store i32 %c1, ptr %out, align 4
  br label %done

case2:
  %c2 = sub i32 %v89, 73
  store i32 %c2, ptr %out, align 4
  br label %done

case_default:
  %cd = add i32 %v89, %a
  store i32 %cd, ptr %out, align 4
  br label %done

done:
  %loaded = load i32, ptr %out, align 4
  %res = and i32 %loaded, 0
  ret i32 %res
}

define i32 @main() {
entry:
  %slot = alloca i32, align 4
  store i32 0, ptr %slot, align 4
  %ret = call i32 @bounded_recursion_target(i32 23, i32 17, ptr %slot)
  %stored = load i32, ptr %slot, align 4
  %ret.ok = icmp eq i32 %ret, 0
  %stored.ok = icmp ne i32 %stored, 0
  %ok = and i1 %ret.ok, %stored.ok
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}_s{{[0-9]+}}_h0 = private unnamed_addr constant
; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %a, i32 %b, ptr %out, i64 %obf.hidden_token)
; VM: %vm.island.root.route{{[0-9]*}} = load i32, ptr %vm.island.state.island
; VM: switch i32 %vm.island.root.route{{[0-9]*}}
; VM-NOT: @__obf_vm_hs_
; VM: call i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %vm.island.state)
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
; VM-DAG: define internal i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %vm.island.subhelper.state)
; VM-DAG: "vm.island.helper.split"
; VM-DAG: "vm.island.helper.large"
; VM-DAG: "vm.island.leaf"
; VM-DAG: "vm.island.leaf.route"
; VM-DAG: "vm.island.leaf.table.shard"
; VM-DAG: "vm.island.recursive.split"
; VM-DAG: "vm.island.recursive.depth.1"
; VM-DAG: "vm.island.root.small"
; VM-DAG: "vm.island.subhelper"
; VM-DAG: "vm.island.subroute"
; VM-DAG: "vm.island.subtable.shard"
; VM-NOT: obf.vm.dispatch.index.bank
