; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-handler-shape-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_target_'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-handler-shape-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-handler-shape-polymorphism.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @arith_mix_a(i32 %x, i32 %y) {
entry:
  %sum = add i32 %x, %y
  %masked = xor i32 %sum, 85
  %both = and i32 %masked, 255
  %wide = or i32 %both, 1024
  %ret = sub i32 %wide, %x
  ret i32 %ret
}

define i64 @arith_mix_b(i64 %x, i64 %y) {
entry:
  %lhs = xor i64 %x, 1311768467463790320
  %rhs = or i64 %y, 255
  %sum = add i64 %lhs, %rhs
  %mask = and i64 %sum, 281474976710655
  %ret = sub i64 %mask, %y
  ret i64 %ret
}

define i32 @compare_route(i32 %x, i32 %y) {
entry:
  %sum = add i32 %x, 7
  %diff = sub i32 %y, 3
  %cmp = icmp ult i32 %sum, %diff
  %ret = select i1 %cmp, i32 %sum, i32 %diff
  ret i32 %ret
}

define i32 @branch_route(i32 %x, i32 %y) {
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

define i32 @main() {
entry:
  %a = call i32 @arith_mix_a(i32 9, i32 12)
  %b = call i64 @arith_mix_b(i64 17, i64 23)
  %c = call i32 @compare_route(i32 5, i32 20)
  %d = call i32 @branch_route(i32 14, i32 3)
  %a.ok = icmp eq i32 %a, 1079
  %b.ok = icmp eq i64 %b, 95075992133577
  %c.ok = icmp eq i32 %c, 12
  %d.ok = icmp eq i32 %d, 22
  %ab.ok = and i1 %a.ok, %b.ok
  %cd.ok = and i1 %c.ok, %d.ok
  %ok = and i1 %ab.ok, %cd.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; VM-LABEL: define i32 @arith_mix_a(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i64 @arith_mix_b(i64 %x, i64 %y)
; VM: call i64 %{{[^ ]+}}(i64 %x, i64 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @compare_route(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-LABEL: define i32 @branch_route(i32 %x, i32 %y)
; VM: call i32 %{{[^ ]+}}(i32 %x, i32 %y, i64 %{{[^)]+}})
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: define internal i64 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i64 %x, i64 %y, i64 %obf.hidden_token)
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i32 %y, i64 %obf.hidden_token)
; VM-DAG: vm.handler.shape.direct
; VM-DAG: vm.handler.shape.temp
; VM-DAG: vm.handler.shape.neutral
