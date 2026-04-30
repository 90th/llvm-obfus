; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-choreography-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-choreography-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-choreography-polymorphism.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @helper_choreo_branch(i32 %x, i32 %y) {
entry:
  %a0 = add i32 %x, 4
  %a1 = xor i32 %a0, %y
  %a2 = add i32 %a1, 9
  %a3 = and i32 %a2, 63
  %a4 = or i32 %a3, 8
  %a5 = sub i32 %a4, 3
  %a6 = add i32 %a5, %x
  %a7 = xor i32 %a6, 5
  %a8 = add i32 %a7, %y
  %a9 = and i32 %a8, 127
  %a10 = add i32 %a9, 6
  %a11 = sub i32 %a10, 2
  %a12 = add i32 %a11, 1
  %a13 = xor i32 %a12, 3
  %a14 = sub i32 %a13, 1
  %a15 = add i32 %a14, 0
  %a16 = and i32 %a15, 255
  %a17 = add i32 %a16, 2
  %cmp = icmp sgt i32 %a17, 40
  br i1 %cmp, label %then, label %else

then:
  %t0 = sub i32 %a17, 7
  %t1 = add i32 %t0, 2
  ret i32 %t1

else:
  %e0 = add i32 %a17, 11
  %e1 = sub i32 %e0, 1
  ret i32 %e1
}

define i32 @helper_choreo_switch(i32 %x) {
entry:
  %a0 = add i32 %x, 5
  %a1 = mul i32 %a0, 3
  %a2 = xor i32 %a1, 12
  %a3 = add i32 %a2, 9
  %a4 = sub i32 %a3, 4
  %a5 = and i32 %a4, 63
  %a6 = or i32 %a5, 2
  %a7 = xor i32 %a6, 7
  %a8 = add i32 %a7, 11
  %a9 = sub i32 %a8, 5
  %a10 = and i32 %a9, 31
  %a11 = add i32 %a10, 1
  %a12 = xor i32 %a11, 16
  %a13 = lshr i32 %a12, 1
  %a14 = add i32 %a13, 6
  %a15 = sub i32 %a14, 8
  %a16 = and i32 %a15, 3
  %a17 = add i32 %a16, 4
  %a18 = sub i32 %a17, 4
  switch i32 %a18, label %default [
    i32 0, label %case0
    i32 1, label %case1
    i32 2, label %case2
  ]

case0:
  ret i32 10

case1:
  ret i32 20

case2:
  ret i32 30

default:
  ret i32 40
}

define i32 @helper_choreo_chain(i32 %x) {
entry:
  %v1 = add i32 %x, 3
  %v2 = mul i32 %v1, 5
  %v3 = xor i32 %v2, 12
  %v4 = add i32 %v3, 9
  %v5 = sub i32 %v4, 4
  %v6 = and i32 %v5, 127
  %v7 = or i32 %v6, 8
  %v8 = shl i32 %v7, 1
  %v9 = lshr i32 %v8, 2
  %v10 = add i32 %v9, 17
  %v11 = xor i32 %v10, 3
  %v12 = add i32 %v11, 6
  %v13 = sub i32 %v12, 5
  %v14 = mul i32 %v13, 2
  %v15 = lshr i32 %v14, 1
  %v16 = add i32 %v15, 11
  %v17 = and i32 %v16, 63
  %v18 = xor i32 %v17, 8
  %v19 = add i32 %v18, 5
  %v20 = sub i32 %v19, 9
  %v21 = add i32 %v20, 4
  %v22 = sub i32 %v21, 4
  %v23 = or i32 %v22, 0
  %v24 = and i32 %v23, 255
  ret i32 %v24
}

define void @helper_choreo_void(ptr %dst, i32 %x) {
entry:
  %v1 = add i32 %x, 17
  %v2 = xor i32 %v1, 5
  %v3 = add i32 %v2, 9
  %v4 = sub i32 %v3, 4
  %v5 = and i32 %v4, 127
  %v6 = or i32 %v5, 2
  %v7 = xor i32 %v6, 7
  %v8 = add i32 %v7, 11
  %v9 = sub i32 %v8, 5
  %v10 = and i32 %v9, 63
  %v11 = add i32 %v10, 1
  %v12 = xor i32 %v11, 16
  %v13 = sub i32 %v12, 7
  %v14 = add i32 %v13, 6
  %v15 = and i32 %v14, 127
  %v16 = xor i32 %v15, 9
  %v17 = add i32 %v16, 4
  %v18 = sub i32 %v17, 3
  %v19 = add i32 %v18, 2
  %v20 = sub i32 %v19, 1
  %v21 = and i32 %v20, 255
  %v22 = add i32 %v21, 0
  %v23 = xor i32 %v22, 0
  %v24 = sub i32 %v23, 0
  store i32 %v24, ptr %dst, align 4
  ret void
}

define i32 @main() {
entry:
  %dst = alloca i32, align 4
  store i32 0, ptr %dst, align 4
  %a = call i32 @helper_choreo_branch(i32 14, i32 9)
  %b = call i32 @helper_choreo_switch(i32 2)
  %c = call i32 @helper_choreo_chain(i32 4)
  call void @helper_choreo_void(ptr %dst, i32 8)
  %d = load i32, ptr %dst, align 4
  %a.ok = icmp eq i32 %a, 63
  %b.ok = icmp eq i32 %b, 30
  %c.ok = icmp eq i32 %c, 44
  %d.ok = icmp eq i32 %d, 53
  %ab.ok = and i1 %a.ok, %b.ok
  %cd.ok = and i1 %c.ok, %d.ok
  %ok = and i1 %ab.ok, %cd.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; VM-LABEL: define i32 @helper_choreo_branch(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @helper_choreo_switch(i32 %x)
; VM: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; VM-LABEL: define i32 @helper_choreo_chain(i32 %x)
; VM: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; VM-LABEL: define void @helper_choreo_void(ptr %dst, i32 %x)
; VM: call void %{{[^ ]+}}(ptr %dst, i32 %x, i64 %{{[^)]+}})
; VM-DAG: "vm.choreo.status.{{[^"]+}}"
; VM-DAG: "vm.choreo.route.{{[^"]+}}"
; VM-DAG: "vm.choreo.dispatch.{{[^"]+}}"
; VM-DAG: "vm.island.root.small"
; VM-DAG: "vm.island.helper.dispatch"
; VM-DAG: "vm.island.subroute"
; VM-NOT: @__obf_vm_seed_resolve
