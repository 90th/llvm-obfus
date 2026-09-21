; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=1 -passes=obf-instruction-substitute -S %s -o %t.seed1.ll
; RUN: %FileCheck %s --check-prefixes=STRUCT,OR < %t.seed1.ll
; RUN: %opt -passes=verify -disable-output %t.seed1.ll
; RUN: %lli %t.seed1.ll
; RUN: %opt -passes='instcombine,verify' -S %t.seed1.ll -o %t.seed1.instcombine.ll
; RUN: %FileCheck %s --check-prefix=OPT < %t.seed1.instcombine.ll
; RUN: %lli %t.seed1.instcombine.ll
; RUN: %opt -O2 -S %t.seed1.ll -o %t.seed1.o2.ll
; RUN: %lli %t.seed1.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=2 -passes=obf-instruction-substitute -S %s -o %t.seed2.ll
; RUN: %FileCheck %s --check-prefixes=STRUCT,AND < %t.seed2.ll
; RUN: %opt -passes=verify -disable-output %t.seed2.ll
; RUN: %lli %t.seed2.ll
; RUN: %opt -passes='instcombine,verify' -S %t.seed2.ll -o %t.seed2.instcombine.ll
; RUN: %FileCheck %s --check-prefix=OPT < %t.seed2.instcombine.ll
; RUN: %lli %t.seed2.instcombine.ll
; RUN: %opt -O2 -S %t.seed2.ll -o %t.seed2.o2.ll
; RUN: %lli %t.seed2.o2.ll
;
; The original @value always returns 255: `and undef, 0` is 0 and
; `or undef, -1` is -1. Separate uses of the same undef-tainted SSA value
; in an expanded identity are not required to choose the same bit pattern.
;
; STRUCT-LABEL: define i32 @value(i32 %x)
; STRUCT-DAG: %obf.subst.lhs.stable = freeze i32 %x
; STRUCT-DAG: %obf.subst.lhs.poison = mul i32 %x, 0
; STRUCT-DAG: %dummy0 = {{.*}} i32 {{.*}}, %obf.subst.lhs.poison
; AND-DAG: freeze i32 %unstable
; AND-DAG: %obf.and.or2 = or i32
; AND-DAG: %obf.and.xor2 = xor i32
; OR-DAG: freeze i32 undef
; OR-DAG: %obf.or.and2{{[0-9]*}} = and i32
; OR-DAG: %obf.or.xor2{{[0-9]*}} = xor i32
;
; OPT-LABEL: define i32 @value(i32 %x)
; OPT: ret i32 255

define i32 @value(i32 %x) {
entry:
  %dummy0 = xor i32 %x, 5
  %dummy1 = or i32 %dummy0, 2
  %unstable = select i1 true, i32 undef, i32 7
  %a = and i32 %unstable, 0
  %o = or i32 undef, -1
  %mix = or i32 %a, %o
  %r = and i32 %mix, 255
  ret i32 %r
}

define i32 @main() {
entry:
  %value = call i32 @value(i32 6)
  %ok = icmp eq i32 %value, 255
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
