; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-table-choreography.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_' --implicit-check-not='@__obf_vm_seedcase_' --implicit-check-not='__obf_vm_h_table_choreo_' --implicit-check-not='__obf_vm_hs_table_choreo_'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-table-choreography.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-helper-table-choreography.yaml -passes=obf-safe-pipeline -disable-output %s

@table_data = private global [8 x i32] [i32 5, i32 8, i32 13, i32 21, i32 34, i32 55, i32 89, i32 144], align 16

define i32 @table_choreo_mix(ptr %out, i32 %x, i32 %y) {
entry:
  %a0 = add i32 %x, 5
  %a1 = xor i32 %a0, %y
  %a2 = and i32 %a1, 7
  %p0 = getelementptr inbounds [8 x i32], ptr @table_data, i32 0, i32 %a2
  %v0 = load i32, ptr %p0, align 4
  %a3 = add i32 %v0, %x
  %a4 = xor i32 %a3, 9
  %a5 = and i32 %a4, 7
  %p1 = getelementptr inbounds [8 x i32], ptr @table_data, i32 0, i32 %a5
  %v1 = load i32, ptr %p1, align 4
  %a6 = add i32 %v1, %y
  %a7 = xor i32 %a6, %v0
  %cmp = icmp sgt i32 %a7, 50
  br i1 %cmp, label %then, label %else

then:
  %t0 = add i32 %a7, 7
  %t1 = and i32 %t0, 7
  %tp = getelementptr inbounds [8 x i32], ptr @table_data, i32 0, i32 %t1
  %tv = load i32, ptr %tp, align 4
  %t2 = add i32 %tv, %t0
  store i32 %t2, ptr %out, align 4
  ret i32 %t2

else:
  %e0 = sub i32 %a7, 3
  %e1 = and i32 %e0, 7
  %ep = getelementptr inbounds [8 x i32], ptr @table_data, i32 0, i32 %e1
  %ev = load i32, ptr %ep, align 4
  %e2 = add i32 %ev, %e0
  store i32 %e2, ptr %out, align 4
  ret i32 %e2
}

define i32 @table_choreo_loop(i32 %seed) {
entry:
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %next.i, %body ]
  %acc = phi i32 [ 0, %entry ], [ %next.acc, %body ]
  %idx0 = add i32 %seed, %i
  %idx1 = xor i32 %idx0, %acc
  %idx2 = and i32 %idx1, 7
  %p = getelementptr inbounds [8 x i32], ptr @table_data, i32 0, i32 %idx2
  %val = load i32, ptr %p, align 4
  %mix0 = add i32 %val, %acc
  %mix1 = xor i32 %mix0, %seed
  %cond = icmp slt i32 %i, 5
  br i1 %cond, label %body, label %done

body:
  %next.acc = add i32 %mix1, %i
  %next.i = add i32 %i, 1
  br label %loop

done:
  ret i32 %mix1
}

define i32 @table_choreo_driver(ptr %tmp, i32 %x) {
entry:
  store i32 0, ptr %tmp, align 4
  %a = call i32 @table_choreo_mix(ptr %tmp, i32 %x, i32 19)
  %b = call i32 @table_choreo_loop(i32 %x)
  %c = load i32, ptr %tmp, align 4
  %sum0 = add i32 %a, %b
  %sum1 = add i32 %sum0, %c
  ret i32 %sum1
}

define i32 @main() {
entry:
  %tmp = alloca i32, align 4
  %r = call i32 @table_choreo_driver(ptr %tmp, i32 6)
  %ok = icmp eq i32 %r, 400
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; VM-LABEL: define i32 @table_choreo_mix(ptr %out, i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(ptr %out, i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @table_choreo_loop(i32 %seed)
; VM: call i32 %{{[^ ]+}}(i32 %seed, i64 %{{[^)]+}})
; VM-LABEL: define i32 @table_choreo_driver(ptr %tmp, i32 %x)
; VM: call i32 %{{[^ ]+}}(ptr %tmp, i32 %x, i64 %{{[^)]+}})
; VM-DAG: "vm.island.root.small"
; VM-DAG: "vm.island.helper.table"
; VM-DAG: "vm.island.subtable.shard"
; VM-DAG: "vm.island.table.shard"
; VM-DAG: "vm.choreo.table.{{[^\"]+}}"
; VM-DAG: "vm.choreo.table.{{[^\"]+}}"
; VM-DAG: "vm.choreo.route.{{[^\"]+}}"
; VM-DAG: "vm.choreo.status.{{[^\"]+}}"
; VM-DAG: "vm.choreo.dispatch.{{[^\"]+}}"
; VM-NOT: @__obf_vm_seed_resolve
