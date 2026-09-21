; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mba-undef-semantics.yaml -passes=obf-vm -S %s -o %t.raw.ll
; RUN: %FileCheck %s --check-prefix=STRUCT < %t.raw.ll
; RUN: %opt -passes=verify -disable-output %t.raw.ll
; RUN: %lli %t.raw.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.raw.ll -o %t.instcombine.ll
; RUN: %lli %t.instcombine.ll
; RUN: %opt -O2 -S %t.raw.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
;
; VM lowering reaches the same public MBA boundary. Loads from VM slots can be
; undef or poison, so add/sub/xor, expanded constant multiplication, and
; negative-power-of-two multiplication must stabilize reused values while
; retaining a poison-dependent guard.
;
; STRUCT: freeze i32
; STRUCT: mul i32 %{{[^,]+}}, 0
; STRUCT-COUNT-2: %obf.vm.mul.lhs.stable{{[0-9]*}} = freeze i32
; STRUCT-DAG: obf.mba.add
; STRUCT-DAG: obf.mba.sub
; STRUCT-DAG: obf.mba.xor
; STRUCT-DAG: obf.vm.mul

define i32 @vm_int_mba_stability(i32 %x, i32 %y) {
entry:
  %a = add i32 %x, %y
  %s = sub i32 %a, %y
  %z = xor i32 %s, %x
  %m = mul i32 %z, 7
  ret i32 %m
}

define i32 @vm_int_undef_mba() {
entry:
  %unstable.add = and i32 undef, 1
  %sum = add i32 %unstable.add, 7
  %is.seven = icmp eq i32 %sum, 7
  %is.eight = icmp eq i32 %sum, 8
  %sum.in.range = or i1 %is.seven, %is.eight
  %unstable.neg = and i32 undef, 1
  %neg = mul i32 %unstable.neg, -1
  %is.zero = icmp eq i32 %neg, 0
  %is.minus.one = icmp eq i32 %neg, -1
  %neg.in.range = or i1 %is.zero, %is.minus.one
  %in.range = and i1 %sum.in.range, %neg.in.range
  %ret = select i1 %in.range, i32 0, i32 1
  ret i32 %ret
}

define i32 @main() {
entry:
  %stable = call i32 @vm_int_mba_stability(i32 17, i32 29)
  %undef = call i32 @vm_int_undef_mba()
  %ok.stable = icmp eq i32 %stable, 0
  %ok.undef = icmp eq i32 %undef, 0
  %ok = and i1 %ok.stable, %ok.undef
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
