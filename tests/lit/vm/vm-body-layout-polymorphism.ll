; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-body-layout-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-body-layout-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-body-layout-polymorphism.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @body_layout_target(i32 %x, i32 %y) {
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
  %ret = call i32 @body_layout_target(i32 13, i32 6)
  %ok = icmp eq i32 %ret, 1591
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: "vm.body.layout.{{logical|permuted|family}}"
; VM-DAG: "vm.trap.shape.{{direct|twohop|slot|gated}}"
; VM-DAG: "vm.island.topology.helper_shards"
; VM-DAG: "vm.island.root.route"
; VM-DAG: "vm.island.subhelper"
; VM-DAG: "vm.island.subroute"
; VM-DAG: "vm.handler.route.trampoline"
; VM-DAG: call i32 @__obf_vm_h_{{[A-Za-z0-9_]+}}(ptr %{{.*vm\.island\.state.*}})
; VM-DAG: call i32 @__obf_vm_hs_{{[A-Za-z0-9_]+}}(ptr %{{.*vm\.island\.state.*}})