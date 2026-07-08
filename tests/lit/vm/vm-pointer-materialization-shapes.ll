; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-pointer-materialization-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=STRUCTURE --implicit-check-not='@__obf_vm_seed_resolve' --implicit-check-not='@__obf_vm_seedcase_strong_target_' --implicit-check-not='@__obf_vm_target_strong_target_'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-pointer-materialization-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=SHAPES
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-pointer-materialization-shapes.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @strong_target_a(i32 %x) {
entry:
  %xor = xor i32 %x, 17
  %sum = add i32 %xor, 9
  ret i32 %sum
}

define i32 @strong_target_b(i32 %x) {
entry:
  %sum = add i32 %x, 11
  %xor = xor i32 %sum, 3
  ret i32 %xor
}

define i32 @strong_target_c(i32 %x) {
entry:
  %mul = mul i32 %x, 5
  %sub = sub i32 %mul, 4
  ret i32 %sub
}

define i32 @main() {
entry:
  %a = call i32 @strong_target_a(i32 5)
  %b = call i32 @strong_target_b(i32 9)
  %c = call i32 @strong_target_c(i32 7)
  %a.ok = icmp eq i32 %a, 29
  %b.ok = icmp eq i32 %b, 23
  %c.ok = icmp eq i32 %c, 31
  %ab.ok = and i1 %a.ok, %b.ok
  %ok = and i1 %ab.ok, %c.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; STRUCTURE-LABEL: define i32 @strong_target_a(i32 %x)
; STRUCTURE: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; STRUCTURE-LABEL: define i32 @strong_target_b(i32 %x)
; STRUCTURE: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; STRUCTURE-LABEL: define i32 @strong_target_c(i32 %x)
; STRUCTURE: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; STRUCTURE-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; STRUCTURE-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; STRUCTURE-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)

; SHAPES-LABEL: define i32 @strong_target_a(i32 %x)
; SHAPES: {{.*}}.ptrmat.{{split|addsub}}
; SHAPES: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; SHAPES-NOT: {{.*}}.ptrmat.direct
; SHAPES: ret i32

; SHAPES-LABEL: define i32 @strong_target_b(i32 %x)
; SHAPES: {{.*}}.ptrmat.{{split|addsub}}
; SHAPES: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; SHAPES-NOT: {{.*}}.ptrmat.direct
; SHAPES: ret i32

; SHAPES-LABEL: define i32 @strong_target_c(i32 %x)
; SHAPES: {{.*}}.ptrmat.{{split|addsub}}
; SHAPES: call i32 %{{[^ ]+}}(i32 %x, i64 %{{[^)]+}})
; SHAPES-NOT: {{.*}}.ptrmat.direct
; SHAPES: ret i32

; SHAPES-DAG: .ptrmat.split
; SHAPES-DAG: .ptrmat.addsub
