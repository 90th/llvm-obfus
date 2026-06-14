; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-handler-family-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-handler-family-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-handler-family-polymorphism.yaml -passes=obf-safe-pipeline -disable-output %s

@glob = internal global [5 x i32] [i32 3, i32 5, i32 7, i32 11, i32 13], align 16

define i32 @family_compare_route(i32 %x, i32 %y) {
entry:
  %lhs = add i32 %x, 7
  %rhs = sub i32 %y, 3
  %cmp = icmp ult i32 %lhs, %rhs
  %ret = select i1 %cmp, i32 %lhs, i32 %rhs
  ret i32 %ret
}

define i32 @family_branch_route(i32 %x, i32 %y) {
entry:
  %mix = xor i32 %x, %y
  %cmp = icmp sgt i32 %mix, 10
  br i1 %cmp, label %then, label %else

then:
  %a = add i32 %mix, 9
  ret i32 %a

else:
  %b = sub i32 %mix, 4
  ret i32 %b
}

define i32 @family_memory_route(ptr %src, ptr %dst, i32 %delta) {
entry:
  %loaded = load i32, ptr %src, align 4
  %mixed = add i32 %loaded, %delta
  store i32 %mixed, ptr %dst, align 4
  %check = load i32, ptr %dst, align 4
  ret i32 %check
}

define i32 @family_gep_route(i32 %index) {
entry:
  %masked = and i32 %index, 3
  %wide = sext i32 %masked to i64
  %ptr = getelementptr inbounds [5 x i32], ptr @glob, i64 0, i64 %wide
  %val = load i32, ptr %ptr, align 4
  ret i32 %val
}

define i32 @main() {
entry:
  %src = alloca i32, align 4
  %dst = alloca i32, align 4
  store i32 30, ptr %src, align 4
  store i32 0, ptr %dst, align 4
  %a = call i32 @family_compare_route(i32 5, i32 20)
  %b = call i32 @family_branch_route(i32 14, i32 3)
  %c = call i32 @family_memory_route(ptr %src, ptr %dst, i32 12)
  %d = call i32 @family_gep_route(i32 2)
  %a.ok = icmp eq i32 %a, 12
  %b.ok = icmp eq i32 %b, 22
  %c.ok = icmp eq i32 %c, 42
  %d.ok = icmp eq i32 %d, 7
  %ab.ok = and i1 %a.ok, %b.ok
  %cd.ok = and i1 %c.ok, %d.ok
  %ok = and i1 %ab.ok, %cd.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; VM-LABEL: define i32 @family_compare_route(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @family_branch_route(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @family_memory_route(ptr %src, ptr %dst, i32 %delta)
; VM: call i32 %{{[^ ]+}}(ptr %src, ptr %dst, i32 %delta, i64 %{{[^)]+}})
; VM-LABEL: define i32 @family_gep_route(i32 %index)
; VM: call i32 %{{[^ ]+}}(i32 %index, i64 %{{[^)]+}})
; VM-DAG: vm.compare.shape.
; VM-DAG: vm.branch.shape.
; VM-DAG: vm.memory.shape.
; VM-DAG: vm.gep.shape.
; VM-DAG: vm.return.shape.
; VM-DAG: ret i32 %obf.vm.ret.encoded
