; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-funnel-shifts.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status] | join("|")' | %FileCheck %s --check-prefix=ADMIT
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %s -o %t.reference.ll
; RUN: %lli %t.reference.ll
; RUN: for seed in 1 2 387541; do \
; RUN:   %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-funnel-shifts.yaml --obf-seed=$seed -passes='obf-vm,verify' -S %s -o %t.$seed.ll && \
; RUN:   %FileCheck %s --check-prefix=VM --implicit-check-not='call {{.*}}@llvm.fsh{{[lr]}}.i' < %t.$seed.ll && \
; RUN:   %lli %t.$seed.ll && \
; RUN:   %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.$seed.ll -o %t.$seed.instcombine.ll && \
; RUN:   %lli %t.$seed.instcombine.ll && \
; RUN:   %opt -O2 -S %t.$seed.ll -o %t.$seed.o2.ll && \
; RUN:   %lli %t.$seed.o2.ll || exit 1; \
; RUN: done
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-funnel-shifts.yaml -passes='obf-safe-pipeline,verify' -S %s -o %t.safe.ll
; RUN: %lli %t.safe.ll

; Normalize only the native reference so the Windows JIT uses consistent
; freeze choices. VM lowering below still receives the original unoptimized IR.
; Frozen arbitrary inputs keep the bounded-output and shared-choice oracles
; valid without requiring one specific value for undef or poison.
; See https://llvm.org/docs/LangRef.html#llvm-fshl-intrinsic,
; https://llvm.org/docs/LangRef.html#llvm-fshr-intrinsic, and
; https://llvm.org/docs/LangRef.html#freeze-instruction.
; Unused poison and caller-frozen poison results must not introduce immediate
; UB through VM handler branches; these cases intentionally keep poison inputs.
declare i1 @llvm.fshl.i1(i1, i1, i1)
declare i1 @llvm.fshr.i1(i1, i1, i1)
declare i8 @llvm.fshl.i8(i8, i8, i8)
declare i8 @llvm.fshr.i8(i8, i8, i8)

@observed.funnel.left = global i8 0
@observed.funnel.right = global i8 0

; For every concrete frozen count, the single bit cannot reach the extracted
; half. The same count must govern both shifts and the zero boundary.
define i8 @vm_funnel_undef_count_left() {
entry:
  %count = freeze i8 undef
  %result = call i8 @llvm.fshl.i8(i8 0, i8 1, i8 %count)
  ret i8 %result
}

define i8 @vm_funnel_undef_count_right() {
entry:
  %count = freeze i8 undef
  %result = call i8 @llvm.fshr.i8(i8 128, i8 0, i8 %count)
  ret i8 %result
}

; All frozen i1 counts are zero modulo width. Freeze the ignored half too,
; so left and right must return their distinct concrete boundary values.
define i1 @vm_funnel_undef_one_left() {
entry:
  %other = freeze i1 undef
  %count = freeze i1 undef
  %result = call i1 @llvm.fshl.i1(i1 true, i1 %other, i1 %count)
  ret i1 %result
}

define i1 @vm_funnel_undef_one_right() {
entry:
  %other = freeze i1 undef
  %count = freeze i1 undef
  %result = call i1 @llvm.fshr.i1(i1 %other, i1 false, i1 %count)
  ret i1 %result
}

; Zero and exactly-width counts ignore the frozen arbitrary unobserved half.
define i8 @vm_funnel_undef_zero_left() {
entry:
  %other = freeze i8 undef
  %result = call i8 @llvm.fshl.i8(i8 37, i8 %other, i8 0)
  ret i8 %result
}

define i8 @vm_funnel_undef_width_right() {
entry:
  %other = freeze i8 undef
  %result = call i8 @llvm.fshr.i8(i8 %other, i8 91, i8 8)
  ret i8 %result
}

; Frozen arbitrary data can determine the imported bit, not the known bits.
define i8 @vm_funnel_undef_data_left() {
entry:
  %other = freeze i8 undef
  %result = call i8 @llvm.fshl.i8(i8 1, i8 %other, i8 1)
  ret i8 %result
}

define i8 @vm_funnel_undef_data_right() {
entry:
  %other = freeze i8 undef
  %result = call i8 @llvm.fshr.i8(i8 %other, i8 128, i8 1)
  ret i8 %result
}

; Count and either data operand may be poison even when the result is unused.
; Non-power-of-two count reduction would itself produce poison without freeze.
declare i3 @llvm.fshl.i3(i3, i3, i3)
declare i3 @llvm.fshr.i3(i3, i3, i3)

define i32 @vm_funnel_discard_poison() {
entry:
  %left.count = call i8 @llvm.fshl.i8(i8 17, i8 23, i8 poison)
  %right.count = call i8 @llvm.fshr.i8(i8 17, i8 23, i8 poison)
  %left.data = call i8 @llvm.fshl.i8(i8 poison, i8 23, i8 0)
  %right.data = call i8 @llvm.fshr.i8(i8 17, i8 poison, i8 8)
  %left.odd = call i3 @llvm.fshl.i3(i3 1, i3 2, i3 poison)
  %right.odd = call i3 @llvm.fshr.i3(i3 1, i3 2, i3 poison)
  ret i32 0
}

define i8 @vm_funnel_freeze_poison_left() {
entry:
  %count = add i8 poison, 1
  %result = call i8 @llvm.fshl.i8(i8 poison, i8 23, i8 %count)
  %safe = freeze i8 %result
  ret i8 %safe
}

define i8 @vm_funnel_freeze_poison_right() {
entry:
  %count = sub i8 8, poison
  %result = call i8 @llvm.fshr.i8(i8 17, i8 poison, i8 %count)
  %safe = freeze i8 %result
  ret i8 %safe
}

; Frozen arbitrary data and counts must stay consistent through inverse
; rotations. Both intrinsics and the comparison use the same frozen choices.
define i1 @vm_funnel_frozen_rotation() {
entry:
  %value = freeze i8 undef
  %count = freeze i8 undef
  %left = call i8 @llvm.fshl.i8(i8 %value, i8 %value, i8 %count)
  %restored = call i8 @llvm.fshr.i8(i8 %left, i8 %left, i8 %count)
  %bad = icmp ne i8 %restored, %value
  ret i1 %bad
}

; Check every i8 count, starting at a frozen arbitrary offset, against the
; LangRef's widened-concatenation definition. The i16 oracle shifts are always
; in range, including zero; they do not mirror the VM's complementary shifts.
; Also check a fixed distinct pair so a zero choice for both frozen data inputs
; cannot make a wrong shift or a wrong zero-boundary selection invisible.
define i1 @vm_funnel_frozen_distinct() {
entry:
  %a = freeze i8 poison
  %b = freeze i8 undef
  %count.base = freeze i8 undef
  %a.wide = zext i8 %a to i16
  %b.wide = zext i8 %b to i16
  %a.high = shl i16 %a.wide, 8
  %concat = or i16 %a.high, %b.wide
  br label %loop

loop:
  %iteration = phi i8 [ 0, %entry ], [ %next, %loop ]
  %errors = phi i1 [ false, %entry ], [ %bad, %loop ]
  %count = add i8 %count.base, %iteration
  %left = call i8 @llvm.fshl.i8(i8 %a, i8 %b, i8 %count)
  %right = call i8 @llvm.fshr.i8(i8 %a, i8 %b, i8 %count)
  %fixed.left = call i8 @llvm.fshl.i8(i8 165, i8 90, i8 %count)
  %fixed.right = call i8 @llvm.fshr.i8(i8 165, i8 90, i8 %count)
  %count.wide = zext i8 %count to i16
  %count.mod = urem i16 %count.wide, 8
  %concat.left = shl i16 %concat, %count.mod
  %left.high = lshr i16 %concat.left, 8
  %expected.left = trunc i16 %left.high to i8
  %concat.right = lshr i16 %concat, %count.mod
  %expected.right = trunc i16 %concat.right to i8
  %fixed.concat.left = shl i16 42330, %count.mod
  %fixed.left.high = lshr i16 %fixed.concat.left, 8
  %expected.fixed.left = trunc i16 %fixed.left.high to i8
  %fixed.concat.right = lshr i16 42330, %count.mod
  %expected.fixed.right = trunc i16 %fixed.concat.right to i8
  %bad0 = icmp ne i8 %left, %expected.left
  %bad1 = icmp ne i8 %right, %expected.right
  %bad2 = icmp ne i8 %fixed.left, %expected.fixed.left
  %bad3 = icmp ne i8 %fixed.right, %expected.fixed.right
  %bad01 = or i1 %bad0, %bad1
  %bad23 = or i1 %bad2, %bad3
  %bad.current = or i1 %bad01, %bad23
  %bad = or i1 %errors, %bad.current
  %next = add i8 %iteration, 1
  %finished = icmp eq i8 %next, 0
  br i1 %finished, label %exit, label %loop

exit:
  ret i1 %bad
}

define i32 @main() {
entry:
  %undef.left = call i8 @vm_funnel_undef_count_left()
  %undef.right = call i8 @vm_funnel_undef_count_right()
  %one.left = call i1 @vm_funnel_undef_one_left()
  %one.right = call i1 @vm_funnel_undef_one_right()
  %zero.left = call i8 @vm_funnel_undef_zero_left()
  %width.right = call i8 @vm_funnel_undef_width_right()
  %data.left = call i8 @vm_funnel_undef_data_left()
  %data.right = call i8 @vm_funnel_undef_data_right()
  %discarded = call i32 @vm_funnel_discard_poison()
  %frozen.left = call i8 @vm_funnel_freeze_poison_left()
  %frozen.right = call i8 @vm_funnel_freeze_poison_right()
  store volatile i8 %frozen.left, ptr @observed.funnel.left
  store volatile i8 %frozen.right, ptr @observed.funnel.right
  %rotation.bad = call i1 @vm_funnel_frozen_rotation()
  %distinct.bad = call i1 @vm_funnel_frozen_distinct()
  %bad0 = icmp ne i8 %undef.left, 0
  %bad1 = icmp ne i8 %undef.right, 0
  %bad2 = icmp ne i1 %one.left, true
  %bad3 = icmp ne i1 %one.right, false
  %bad4 = icmp ne i8 %zero.left, 37
  %bad5 = icmp ne i8 %width.right, 91
  %known.left = and i8 %data.left, 254
  %known.right = and i8 %data.right, 127
  %bad6 = icmp ne i8 %known.left, 2
  %bad7 = icmp ne i8 %known.right, 64
  %bad8 = icmp ne i32 %discarded, 0
  %errors0 = or i1 %bad0, %bad1
  %errors1 = or i1 %errors0, %bad2
  %errors2 = or i1 %errors1, %bad3
  %errors3 = or i1 %errors2, %bad4
  %errors4 = or i1 %errors3, %bad5
  %errors5 = or i1 %errors4, %bad6
  %errors6 = or i1 %errors5, %bad7
  %errors7 = or i1 %errors6, %bad8
  %errors8 = or i1 %errors7, %rotation.bad
  %errors9 = or i1 %errors8, %distinct.bad
  %code = zext i1 %errors9 to i32
  ret i32 %code
}

; ADMIT-DAG: vm_funnel_undef_count_left|candidate
; ADMIT-DAG: vm_funnel_undef_count_right|candidate
; ADMIT-DAG: vm_funnel_undef_one_left|candidate
; ADMIT-DAG: vm_funnel_undef_one_right|candidate
; ADMIT-DAG: vm_funnel_undef_zero_left|candidate
; ADMIT-DAG: vm_funnel_undef_width_right|candidate
; ADMIT-DAG: vm_funnel_undef_data_left|candidate
; ADMIT-DAG: vm_funnel_undef_data_right|candidate
; ADMIT-DAG: vm_funnel_discard_poison|candidate
; ADMIT-DAG: vm_funnel_freeze_poison_left|candidate
; ADMIT-DAG: vm_funnel_freeze_poison_right|candidate
; ADMIT-DAG: vm_funnel_frozen_rotation|candidate
; ADMIT-DAG: vm_funnel_frozen_distinct|candidate

; VM-LABEL: define i8 @vm_funnel_undef_count_left()
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_undef_count_left.obf.wrapper.indirect
; VM-LABEL: define i8 @vm_funnel_undef_count_right()
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_undef_count_right.obf.wrapper.indirect
; VM-LABEL: define i32 @vm_funnel_discard_poison()
; VM: entry.obf.vm.wrapper:
; VM: call i32 %vm_funnel_discard_poison.obf.wrapper.indirect
; VM-LABEL: define i8 @vm_funnel_freeze_poison_left()
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_freeze_poison_left.obf.wrapper.indirect
; VM-LABEL: define i8 @vm_funnel_freeze_poison_right()
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_freeze_poison_right.obf.wrapper.indirect
