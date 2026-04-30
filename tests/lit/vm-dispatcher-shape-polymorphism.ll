; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-shape-polymorphism.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-shape-polymorphism.yaml -passes=obf-vm -S %s -o %t
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-dispatcher-shape-polymorphism.yaml -passes=obf-safe-pipeline -disable-output %s

define i32 @dispatch_shape_a(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, 3
  %b = xor i32 %a, %y
  %c = sub i32 %b, 5
  ret i32 %c
}

define i32 @dispatch_shape_b(i32 %x, i32 %y) {
entry:
  %a = mul i32 %x, 7
  %b = add i32 %a, %y
  %c = and i32 %b, 255
  ret i32 %c
}

define i32 @dispatch_shape_c(i32 %x, i32 %y) {
entry:
  %a = or i32 %x, 17
  %b = xor i32 %a, %y
  %c = add i32 %b, 11
  ret i32 %c
}

define i32 @dispatch_shape_d(i32 %x, i32 %y) {
entry:
  %a = sub i32 %x, %y
  %b = xor i32 %a, 51
  %c = add i32 %b, 19
  ret i32 %c
}

define i32 @dispatch_shape_e(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, %y
  %b = shl i32 %a, 1
  %c = xor i32 %b, 123
  ret i32 %c
}

define i32 @dispatch_shape_f(i32 %x, i32 %y) {
entry:
  %a = xor i32 %x, 99
  %b = lshr i32 %a, 1
  %c = add i32 %b, %y
  ret i32 %c
}

define i32 @dispatch_shape_g(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, 29
  %b = and i32 %y, 63
  %c = xor i32 %a, %b
  ret i32 %c
}

define i32 @dispatch_shape_h(i32 %x, i32 %y) {
entry:
  %a = or i32 %x, %y
  %b = sub i32 %a, 13
  %c = xor i32 %b, 7
  ret i32 %c
}

define i32 @dispatch_shape_large_a(i32 %x) {
entry:
  %v01 = add i32 %x, 1
  %v02 = add i32 %v01, 2
  %v03 = add i32 %v02, 3
  %v04 = add i32 %v03, 4
  %v05 = add i32 %v04, 5
  %v06 = add i32 %v05, 6
  %v07 = add i32 %v06, 7
  %v08 = add i32 %v07, 8
  %v09 = add i32 %v08, 9
  %v10 = add i32 %v09, 10
  %v11 = add i32 %v10, 11
  %v12 = add i32 %v11, 12
  %v13 = add i32 %v12, 13
  %v14 = add i32 %v13, 14
  %v15 = add i32 %v14, 15
  %v16 = add i32 %v15, 16
  %v17 = add i32 %v16, 17
  %v18 = add i32 %v17, 18
  %v19 = add i32 %v18, 19
  %v20 = add i32 %v19, 20
  ret i32 %v20
}

define i32 @dispatch_shape_large_b(i32 %x) {
entry:
  %v01 = add i32 %x, 2
  %v02 = add i32 %v01, 3
  %v03 = add i32 %v02, 4
  %v04 = add i32 %v03, 5
  %v05 = add i32 %v04, 6
  %v06 = add i32 %v05, 7
  %v07 = add i32 %v06, 8
  %v08 = add i32 %v07, 9
  %v09 = add i32 %v08, 10
  %v10 = add i32 %v09, 11
  %v11 = add i32 %v10, 12
  %v12 = add i32 %v11, 13
  %v13 = add i32 %v12, 14
  %v14 = add i32 %v13, 15
  %v15 = add i32 %v14, 16
  %v16 = add i32 %v15, 17
  %v17 = add i32 %v16, 18
  %v18 = add i32 %v17, 19
  ret i32 %v18
}

define i32 @main() {
entry:
  %a = call i32 @dispatch_shape_a(i32 10, i32 4)
  %b = call i32 @dispatch_shape_b(i32 6, i32 9)
  %c = call i32 @dispatch_shape_c(i32 8, i32 3)
  %d = call i32 @dispatch_shape_d(i32 20, i32 5)
  %e = call i32 @dispatch_shape_e(i32 7, i32 2)
  %f = call i32 @dispatch_shape_f(i32 100, i32 6)
  %g = call i32 @dispatch_shape_g(i32 1, i32 90)
  %h = call i32 @dispatch_shape_h(i32 12, i32 5)
  %large.a = call i32 @dispatch_shape_large_a(i32 5)
  %large.b = call i32 @dispatch_shape_large_b(i32 9)
  %a.ok = icmp eq i32 %a, 4
  %b.ok = icmp eq i32 %b, 51
  %c.ok = icmp eq i32 %c, 37
  %d.ok = icmp eq i32 %d, 79
  %e.ok = icmp eq i32 %e, 105
  %f.ok = icmp eq i32 %f, 9
  %g.ok = icmp eq i32 %g, 4
  %h.ok = icmp eq i32 %h, 7
  %large.a.ok = icmp eq i32 %large.a, 215
  %large.b.ok = icmp eq i32 %large.b, 198
  %ab.ok = and i1 %a.ok, %b.ok
  %cd.ok = and i1 %c.ok, %d.ok
  %ef.ok = and i1 %e.ok, %f.ok
  %gh.ok = and i1 %g.ok, %h.ok
  %abcd.ok = and i1 %ab.ok, %cd.ok
  %efgh.ok = and i1 %ef.ok, %gh.ok
  %large.ok = and i1 %large.a.ok, %large.b.ok
  %small.ok = and i1 %abcd.ok, %efgh.ok
  %ok = and i1 %small.ok, %large.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; VM-DAG: vm.dispatch.shape.direct
; VM-DAG: vm.dispatch.shape.switch
; VM-DAG: vm.island.topology.helper_shards
; VM-DAG: vm.island.count.
