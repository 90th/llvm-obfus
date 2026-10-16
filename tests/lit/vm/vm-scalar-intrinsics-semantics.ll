; RUN: %python %S/../Inputs/vm_scalar_intrinsics.py --work %t.dir --opt %opt --plugin %obf_plugin --clang %raw_clang --config %S/../Inputs/vm-scalar-intrinsics.yaml --semantics %s --lli %lli
;
; The harness checks native O0/O2 results against independent integer oracles.
; Every selected function must have whole-function VM admission and emission.
; Poison results can be unused or caller-frozen without immediate UB.
; Arbitrary frozen values have relational checks, not one required bit pattern.

target datalayout = "e-p:64:64-i64:64-i128:128-v128:128-n8:16:32:64-S128"

declare i8 @llvm.abs.i8(i8, i1 immarg)
declare i32 @llvm.scmp.i32.i8(i8, i8)
declare i2 @llvm.ucmp.i2.i8(i8, i8)
declare i8 @llvm.uadd.sat.i8(i8, i8)
declare i8 @llvm.usub.sat.i8(i8, i8)
declare i8 @llvm.sadd.sat.i8(i8, i8)
declare i8 @llvm.ssub.sat.i8(i8, i8)
declare { i8, i1 } @llvm.uadd.with.overflow.i8(i8, i8)
declare { i8, i1 } @llvm.sadd.with.overflow.i8(i8, i8)
declare { i8, i1 } @llvm.usub.with.overflow.i8(i8, i8)
declare { i8, i1 } @llvm.ssub.with.overflow.i8(i8, i8)
declare { i8, i1 } @llvm.umul.with.overflow.i8(i8, i8)
declare { i8, i1 } @llvm.smul.with.overflow.i8(i8, i8)
declare i8 @llvm.expect.i8(i8, i8)
declare i8 @llvm.expect.with.probability.i8(i8, i8, double immarg)

@scalar.observed = global i8 0

define i32 @vm_scalar_discard_poison() {
entry:
  %abs = call i8 @llvm.abs.i8(i8 poison, i1 false)
  %minimum = call i8 @llvm.abs.i8(i8 -128, i1 true)
  %scmp = call i32 @llvm.scmp.i32.i8(i8 poison, i8 7)
  %ucmp = call i2 @llvm.ucmp.i2.i8(i8 7, i8 poison)
  %uadd.sat = call i8 @llvm.uadd.sat.i8(i8 poison, i8 7)
  %usub.sat = call i8 @llvm.usub.sat.i8(i8 7, i8 poison)
  %sadd.sat = call i8 @llvm.sadd.sat.i8(i8 poison, i8 7)
  %ssub.sat = call i8 @llvm.ssub.sat.i8(i8 7, i8 poison)
  %uadd = call { i8, i1 } @llvm.uadd.with.overflow.i8(i8 poison, i8 7)
  %sadd = call { i8, i1 } @llvm.sadd.with.overflow.i8(i8 7, i8 poison)
  %usub = call { i8, i1 } @llvm.usub.with.overflow.i8(i8 poison, i8 7)
  %ssub = call { i8, i1 } @llvm.ssub.with.overflow.i8(i8 7, i8 poison)
  %umul = call { i8, i1 } @llvm.umul.with.overflow.i8(i8 poison, i8 7)
  %smul = call { i8, i1 } @llvm.smul.with.overflow.i8(i8 7, i8 poison)
  %expect = call i8 @llvm.expect.i8(i8 poison, i8 7)
  %probability = call i8 @llvm.expect.with.probability.i8(i8 poison, i8 7, double 5.000000e-01)
  ret i32 0
}

define i8 @vm_scalar_freeze_results() {
entry:
  %abs = call i8 @llvm.abs.i8(i8 poison, i1 false)
  %abs.safe = freeze i8 %abs
  %minimum = call i8 @llvm.abs.i8(i8 -128, i1 true)
  %minimum.safe = freeze i8 %minimum
  %scmp = call i32 @llvm.scmp.i32.i8(i8 poison, i8 7)
  %scmp.safe = freeze i32 %scmp
  %scmp.byte = trunc i32 %scmp.safe to i8
  %ucmp = call i2 @llvm.ucmp.i2.i8(i8 7, i8 poison)
  %ucmp.safe = freeze i2 %ucmp
  %ucmp.byte = sext i2 %ucmp.safe to i8
  %uadd.sat = call i8 @llvm.uadd.sat.i8(i8 poison, i8 7)
  %uadd.sat.safe = freeze i8 %uadd.sat
  %usub.sat = call i8 @llvm.usub.sat.i8(i8 7, i8 poison)
  %usub.sat.safe = freeze i8 %usub.sat
  %sadd.sat = call i8 @llvm.sadd.sat.i8(i8 poison, i8 7)
  %sadd.sat.safe = freeze i8 %sadd.sat
  %ssub.sat = call i8 @llvm.ssub.sat.i8(i8 7, i8 poison)
  %ssub.sat.safe = freeze i8 %ssub.sat
  %uadd = call { i8, i1 } @llvm.uadd.with.overflow.i8(i8 poison, i8 7)
  %uadd.value = extractvalue { i8, i1 } %uadd, 0
  %uadd.flag = extractvalue { i8, i1 } %uadd, 1
  %uadd.safe = freeze i8 %uadd.value
  %uadd.flag.safe = freeze i1 %uadd.flag
  %sadd = call { i8, i1 } @llvm.sadd.with.overflow.i8(i8 7, i8 poison)
  %sadd.value = extractvalue { i8, i1 } %sadd, 0
  %sadd.flag = extractvalue { i8, i1 } %sadd, 1
  %sadd.safe = freeze i8 %sadd.value
  %sadd.flag.safe = freeze i1 %sadd.flag
  %usub = call { i8, i1 } @llvm.usub.with.overflow.i8(i8 poison, i8 7)
  %usub.value = extractvalue { i8, i1 } %usub, 0
  %usub.flag = extractvalue { i8, i1 } %usub, 1
  %usub.safe = freeze i8 %usub.value
  %usub.flag.safe = freeze i1 %usub.flag
  %ssub = call { i8, i1 } @llvm.ssub.with.overflow.i8(i8 7, i8 poison)
  %ssub.value = extractvalue { i8, i1 } %ssub, 0
  %ssub.flag = extractvalue { i8, i1 } %ssub, 1
  %ssub.safe = freeze i8 %ssub.value
  %ssub.flag.safe = freeze i1 %ssub.flag
  %umul = call { i8, i1 } @llvm.umul.with.overflow.i8(i8 poison, i8 7)
  %umul.value = extractvalue { i8, i1 } %umul, 0
  %umul.flag = extractvalue { i8, i1 } %umul, 1
  %umul.safe = freeze i8 %umul.value
  %umul.flag.safe = freeze i1 %umul.flag
  %smul = call { i8, i1 } @llvm.smul.with.overflow.i8(i8 7, i8 poison)
  %smul.value = extractvalue { i8, i1 } %smul, 0
  %smul.flag = extractvalue { i8, i1 } %smul, 1
  %smul.safe = freeze i8 %smul.value
  %smul.flag.safe = freeze i1 %smul.flag
  %expect = call i8 @llvm.expect.i8(i8 poison, i8 7)
  %expect.safe = freeze i8 %expect
  %probability = call i8 @llvm.expect.with.probability.i8(i8 poison, i8 7, double 5.000000e-01)
  %probability.safe = freeze i8 %probability
  %flags0 = xor i1 %uadd.flag.safe, %sadd.flag.safe
  %flags1 = xor i1 %usub.flag.safe, %ssub.flag.safe
  %flags2 = xor i1 %umul.flag.safe, %smul.flag.safe
  %flags3 = xor i1 %flags0, %flags1
  %flags = xor i1 %flags3, %flags2
  %flag.byte = zext i1 %flags to i8
  %sum0 = xor i8 %abs.safe, %minimum.safe
  %sum1 = xor i8 %sum0, %scmp.byte
  %sum2 = xor i8 %sum1, %ucmp.byte
  %sum3 = xor i8 %sum2, %uadd.sat.safe
  %sum4 = xor i8 %sum3, %usub.sat.safe
  %sum5 = xor i8 %sum4, %sadd.sat.safe
  %sum6 = xor i8 %sum5, %ssub.sat.safe
  %sum7 = xor i8 %sum6, %uadd.safe
  %sum8 = xor i8 %sum7, %sadd.safe
  %sum9 = xor i8 %sum8, %usub.safe
  %sum10 = xor i8 %sum9, %ssub.safe
  %sum11 = xor i8 %sum10, %umul.safe
  %sum12 = xor i8 %sum11, %smul.safe
  %sum13 = xor i8 %sum12, %expect.safe
  %sum14 = xor i8 %sum13, %probability.safe
  %result = xor i8 %sum14, %flag.byte
  ret i8 %result
}

define i1 @vm_scalar_frozen_choices() {
entry:
  %a = freeze i8 poison
  %b = freeze i8 undef
  %a.wide = sext i8 %a to i16
  %b.wide = sext i8 %b to i16
  %exact = mul i16 %a.wide, %b.wide
  %expected.value = trunc i16 %exact to i8
  %low = icmp slt i16 %exact, -128
  %high = icmp sgt i16 %exact, 127
  %expected.flag = or i1 %low, %high
  %actual = call { i8, i1 } @llvm.smul.with.overflow.i8(i8 %a, i8 %b)
  %actual.value = extractvalue { i8, i1 } %actual, 0
  %actual.flag = extractvalue { i8, i1 } %actual, 1
  %bad.value = icmp ne i8 %actual.value, %expected.value
  %bad.flag = icmp ne i1 %actual.flag, %expected.flag
  %bad.mul = or i1 %bad.value, %bad.flag
  %abs = call i8 @llvm.abs.i8(i8 %a, i1 false)
  %a.negative = icmp slt i16 %a.wide, 0
  %negated = sub i16 0, %a.wide
  %expected.abs.wide = select i1 %a.negative, i16 %negated, i16 %a.wide
  %expected.abs = trunc i16 %expected.abs.wide to i8
  %bad.abs = icmp ne i8 %abs, %expected.abs
  %scmp = call i32 @llvm.scmp.i32.i8(i8 %a, i8 %b)
  %less = icmp slt i16 %a.wide, %b.wide
  %greater = icmp sgt i16 %a.wide, %b.wide
  %less.wide = zext i1 %less to i32
  %greater.wide = zext i1 %greater to i32
  %expected.scmp = sub i32 %greater.wide, %less.wide
  %bad.scmp = icmp ne i32 %scmp, %expected.scmp
  %sum = call i8 @llvm.sadd.sat.i8(i8 %a, i8 0)
  %difference = call i8 @llvm.ssub.sat.i8(i8 %a, i8 0)
  %bad.sum = icmp ne i8 %sum, %a
  %bad.difference = icmp ne i8 %difference, %a
  %errors0 = or i1 %bad.mul, %bad.abs
  %errors1 = or i1 %errors0, %bad.scmp
  %errors2 = or i1 %errors1, %bad.sum
  %errors3 = or i1 %errors2, %bad.difference
  ret i1 %errors3
}

define i1 @vm_scalar_undef_bounds() {
entry:
  %abs = call i8 @llvm.abs.i8(i8 undef, i1 false)
  %abs.nonnegative = icmp sge i8 %abs, 0
  %abs.minimum = icmp eq i8 %abs, -128
  %abs.ok = or i1 %abs.nonnegative, %abs.minimum
  %scmp = call i32 @llvm.scmp.i32.i8(i8 undef, i8 0)
  %scmp.low = icmp sge i32 %scmp, -1
  %scmp.high = icmp sle i32 %scmp, 1
  %scmp.ok = and i1 %scmp.low, %scmp.high
  %ucmp = call i2 @llvm.ucmp.i2.i8(i8 undef, i8 0)
  %ucmp.ok = icmp sle i2 %ucmp, 1
  %ucmp.nonnegative = icmp sge i2 %ucmp, 0
  %uadd.sat = call i8 @llvm.uadd.sat.i8(i8 undef, i8 -1)
  %uadd.ok = icmp eq i8 %uadd.sat, -1
  %usub.sat = call i8 @llvm.usub.sat.i8(i8 undef, i8 -1)
  %usub.ok = icmp eq i8 %usub.sat, 0
  %sadd.sat = call i8 @llvm.sadd.sat.i8(i8 undef, i8 127)
  %sadd.ok = icmp sge i8 %sadd.sat, -1
  %ssub.sat = call i8 @llvm.ssub.sat.i8(i8 undef, i8 -128)
  %ssub.ok = icmp sge i8 %ssub.sat, 0
  %uadd = call { i8, i1 } @llvm.uadd.with.overflow.i8(i8 undef, i8 0)
  %sadd = call { i8, i1 } @llvm.sadd.with.overflow.i8(i8 undef, i8 0)
  %usub = call { i8, i1 } @llvm.usub.with.overflow.i8(i8 undef, i8 0)
  %ssub = call { i8, i1 } @llvm.ssub.with.overflow.i8(i8 undef, i8 0)
  %umul = call { i8, i1 } @llvm.umul.with.overflow.i8(i8 undef, i8 0)
  %smul = call { i8, i1 } @llvm.smul.with.overflow.i8(i8 undef, i8 0)
  %uadd.flag = extractvalue { i8, i1 } %uadd, 1
  %sadd.flag = extractvalue { i8, i1 } %sadd, 1
  %usub.flag = extractvalue { i8, i1 } %usub, 1
  %ssub.flag = extractvalue { i8, i1 } %ssub, 1
  %umul.flag = extractvalue { i8, i1 } %umul, 1
  %smul.flag = extractvalue { i8, i1 } %smul, 1
  %umul.value = extractvalue { i8, i1 } %umul, 0
  %smul.value = extractvalue { i8, i1 } %smul, 0
  %umul.bad = icmp ne i8 %umul.value, 0
  %smul.bad = icmp ne i8 %smul.value, 0
  %expect = call i8 @llvm.expect.i8(i8 17, i8 poison)
  %probability = call i8 @llvm.expect.with.probability.i8(i8 23, i8 undef, double 5.000000e-01)
  %expect.ok = icmp eq i8 %expect, 17
  %probability.ok = icmp eq i8 %probability, 23
  %ok0 = and i1 %abs.ok, %scmp.ok
  %ok1 = and i1 %ok0, %ucmp.ok
  %ok2 = and i1 %ok1, %ucmp.nonnegative
  %ok3 = and i1 %ok2, %uadd.ok
  %ok4 = and i1 %ok3, %usub.ok
  %ok5 = and i1 %ok4, %sadd.ok
  %ok6 = and i1 %ok5, %ssub.ok
  %ok7 = and i1 %ok6, %expect.ok
  %ok8 = and i1 %ok7, %probability.ok
  %bad.bounds = xor i1 %ok8, true
  %flags0 = or i1 %uadd.flag, %sadd.flag
  %flags1 = or i1 %usub.flag, %ssub.flag
  %flags2 = or i1 %umul.flag, %smul.flag
  %flags3 = or i1 %flags0, %flags1
  %flags4 = or i1 %flags3, %flags2
  %bad.mul = or i1 %umul.bad, %smul.bad
  %bad0 = or i1 %bad.bounds, %flags4
  %bad1 = or i1 %bad0, %bad.mul
  ret i1 %bad1
}

define i32 @main() {
entry:
  %discard = call i32 @vm_scalar_discard_poison()
  %frozen = call i8 @vm_scalar_freeze_results()
  store volatile i8 %frozen, ptr @scalar.observed
  %choices = call i1 @vm_scalar_frozen_choices()
  %bounds = call i1 @vm_scalar_undef_bounds()
  %discard.bad = icmp ne i32 %discard, 0
  %bad0 = or i1 %discard.bad, %choices
  %bad1 = or i1 %bad0, %bounds
  %code = zext i1 %bad1 to i32
  ret i32 %code
}
