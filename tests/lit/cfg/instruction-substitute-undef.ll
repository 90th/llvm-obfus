; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=1 -passes='obf-instruction-substitute,verify' -S %s -o %t.seed1.ll
; RUN: %FileCheck %s --check-prefix=STABLE < %t.seed1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=1 -passes='obf-instruction-substitute,verify' -S %s -o %t.seed1.again.ll
; RUN: cmp %t.seed1.ll %t.seed1.again.ll
; RUN: %lli %t.seed1.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.seed1.ll -o %t.seed1.instcombine.ll
; RUN: %lli %t.seed1.instcombine.ll
; RUN: %opt -O2 -S %t.seed1.ll -o %t.seed1.o2.ll
; RUN: %lli %t.seed1.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/instruction-substitute.yaml --obf-seed=2 -passes='obf-instruction-substitute,verify' -S %s -o %t.seed2.ll
; RUN: %FileCheck %s --check-prefix=STABLE < %t.seed2.ll
; RUN: %lli %t.seed2.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.seed2.ll -o %t.seed2.instcombine.ll
; RUN: %lli %t.seed2.instcombine.ll
; RUN: %opt -O2 -S %t.seed2.ll -o %t.seed2.o2.ll
; RUN: %lli %t.seed2.o2.ll
;
; The original @value always returns 255: `and undef, 0` is 0 and
; `or undef, -1` is -1. Expanded identities must not make independent undef
; choices disagree. A freeze of undef can fold away, so check the consumer's
; value rather than the instruction spelling, before and after optimization.
; The dead operations on %x may receive poison without poisoning the result.
; Freeze each observation to avoid a faulty rewrite making the test branch UB.
@value_inputs = private constant [8 x i32] [
  i32 0, i32 1, i32 -1, i32 6, i32 255, i32 65536,
  i32 2147483647, i32 -2147483648
]

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
  %poison.value = call i32 @value(i32 poison)
  %poison.frozen = freeze i32 %poison.value
  %poison.ok = icmp eq i32 %poison.frozen, 255
  %undef.value = call i32 @value(i32 undef)
  %undef.frozen = freeze i32 %undef.value
  %undef.ok = icmp eq i32 %undef.frozen, 255
  %safe = and i1 %poison.ok, %undef.ok
  br i1 %safe, label %loop, label %fail

loop:
  %index = phi i32 [ 0, %entry ], [ %next, %continue ]
  %input.ptr = getelementptr inbounds [8 x i32], ptr @value_inputs, i32 0, i32 %index
  %input = load i32, ptr %input.ptr
  %value = call i32 @value(i32 %input)
  %frozen = freeze i32 %value
  %ok = icmp eq i32 %frozen, 255
  br i1 %ok, label %continue, label %fail

continue:
  %next = add nuw i32 %index, 1
  %more = icmp ult i32 %next, 8
  br i1 %more, label %loop, label %pass

pass:
  ret i32 0

fail:
  ret i32 1
}

; XOR substitution duplicates its operand in either identity family. Require
; the emitted stabilization of the argument, without naming the temporary or
; requiring a freeze of undef that IR construction can legally fold away.
; STABLE-LABEL: define i32 @value(i32 %x)
; STABLE: %{{[A-Za-z0-9$._-]+}} = freeze i32 %x
