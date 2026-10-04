; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-funnel-shifts.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status] | join("|")' | %FileCheck %s --check-prefix=ADMIT
; RUN: printf 'seed: 387541\ndefault_level: none\ntargets:\n  - match: "vm_funnel_*"\n    level: vm\nvm:\n  max_virtual_instructions: 2\n' > %t.budget.yaml
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%t.budget.yaml -passes=obf-feature-report -disable-output %s | jq -r '.predictions[] | select(.pass == "vm") | [.target_name, .status] | join("|")' | %FileCheck %s --check-prefix=BUDGET
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-funnel-shifts.yaml -passes='obf-vm,verify' -S %s -o %t.vm.ll
; RUN: %FileCheck %s --check-prefix=VM --implicit-check-not='call {{.*}}@llvm.fsh{{[lr]}}.i' < %t.vm.ll
; RUN: %python %S/../Inputs/run_funnel_runtime.py %raw_clang %lli %s
; RUN: %python %S/../Inputs/run_funnel_runtime.py %raw_clang %lli %t.vm.ll
; RUN: %opt -O2 -S %t.vm.ll -o %t.o2.ll
; RUN: %python %S/../Inputs/run_funnel_runtime.py %raw_clang %lli %t.o2.ll

; Scalar funnel shifts must be admitted without native intrinsic fallbacks.
; The original call and return fit a two-instruction budget, but the complete
; VM expansion must still count against that budget. Vector forms remain out
; of scope. Runtime oracles use widened concatenation, not the VM expansion.
target datalayout = "e-p:64:64-i64:64-i128:128-v128:128-n8:16:32:64-S128"

declare i1 @llvm.fshl.i1(i1, i1, i1)
declare i1 @llvm.fshr.i1(i1, i1, i1)
declare i3 @llvm.fshl.i3(i3, i3, i3)
declare i3 @llvm.fshr.i3(i3, i3, i3)
declare i8 @llvm.fshl.i8(i8, i8, i8)
declare i8 @llvm.fshr.i8(i8, i8, i8)
declare i64 @llvm.fshl.i64(i64, i64, i64)
declare i64 @llvm.fshr.i64(i64, i64, i64)
declare i127 @llvm.fshl.i127(i127, i127, i127)
declare i127 @llvm.fshr.i127(i127, i127, i127)
declare i128 @llvm.fshl.i128(i128, i128, i128)
declare i128 @llvm.fshr.i128(i128, i128, i128)
declare <2 x i8> @llvm.fshl.v2i8(<2 x i8>, <2 x i8>, <2 x i8>)
declare <2 x i8> @llvm.fshr.v2i8(<2 x i8>, <2 x i8>, <2 x i8>)

define i1 @vm_funnel_left1(i1 %a, i1 %b, i1 %count) {
entry:
  %result = call i1 @llvm.fshl.i1(i1 %a, i1 %b, i1 %count)
  ret i1 %result
}

define i1 @vm_funnel_right1(i1 %a, i1 %b, i1 %count) {
entry:
  %result = call i1 @llvm.fshr.i1(i1 %a, i1 %b, i1 %count)
  ret i1 %result
}

define i3 @vm_funnel_left3(i3 %a, i3 %b, i3 %count) {
entry:
  %result = call i3 @llvm.fshl.i3(i3 %a, i3 %b, i3 %count)
  ret i3 %result
}

define i3 @vm_funnel_right3(i3 %a, i3 %b, i3 %count) {
entry:
  %result = call i3 @llvm.fshr.i3(i3 %a, i3 %b, i3 %count)
  ret i3 %result
}

define i8 @vm_funnel_left8(i8 %a, i8 %b, i8 %count) {
entry:
  %result = call i8 @llvm.fshl.i8(i8 %a, i8 %b, i8 %count)
  ret i8 %result
}

define i8 @vm_funnel_right8(i8 %a, i8 %b, i8 %count) {
entry:
  %result = call i8 @llvm.fshr.i8(i8 %a, i8 %b, i8 %count)
  ret i8 %result
}

define i64 @vm_funnel_left64(i64 %a, i64 %b, i64 %count) {
entry:
  %result = call i64 @llvm.fshl.i64(i64 %a, i64 %b, i64 %count)
  ret i64 %result
}

define i64 @vm_funnel_right64(i64 %a, i64 %b, i64 %count) {
entry:
  %result = call i64 @llvm.fshr.i64(i64 %a, i64 %b, i64 %count)
  ret i64 %result
}

define i127 @vm_funnel_left127(i127 %a, i127 %b, i127 %count) {
entry:
  %result = call i127 @llvm.fshl.i127(i127 %a, i127 %b, i127 %count)
  ret i127 %result
}

define i127 @vm_funnel_right127(i127 %a, i127 %b, i127 %count) {
entry:
  %result = call i127 @llvm.fshr.i127(i127 %a, i127 %b, i127 %count)
  ret i127 %result
}

define i128 @vm_funnel_left128(i128 %a, i128 %b, i128 %count) {
entry:
  %result = call i128 @llvm.fshl.i128(i128 %a, i128 %b, i128 %count)
  ret i128 %result
}

define i128 @vm_funnel_right128(i128 %a, i128 %b, i128 %count) {
entry:
  %result = call i128 @llvm.fshr.i128(i128 %a, i128 %b, i128 %count)
  ret i128 %result
}

define i64 @vm_funnel_rotate_left64(i64 %value, i64 %count) {
entry:
  %result = call i64 @llvm.fshl.i64(i64 %value, i64 %value, i64 %count)
  ret i64 %result
}

define i64 @vm_funnel_rotate_right64(i64 %value, i64 %count) {
entry:
  %result = call i64 @llvm.fshr.i64(i64 %value, i64 %value, i64 %count)
  ret i64 %result
}

define <2 x i8> @vm_funnel_vector_left(<2 x i8> %a, <2 x i8> %b, <2 x i8> %count) {
entry:
  %result = call <2 x i8> @llvm.fshl.v2i8(<2 x i8> %a, <2 x i8> %b, <2 x i8> %count)
  ret <2 x i8> %result
}

define <2 x i8> @vm_funnel_vector_right(<2 x i8> %a, <2 x i8> %b, <2 x i8> %count) {
entry:
  %result = call <2 x i8> @llvm.fshr.v2i8(<2 x i8> %a, <2 x i8> %b, <2 x i8> %count)
  ret <2 x i8> %result
}

define i1 @check1(i1 %a, i1 %b, i1 %count) {
entry:
  %a.wide = zext i1 %a to i2
  %b.wide = zext i1 %b to i2
  %high = shl i2 %a.wide, 1
  %concatenated = or i2 %high, %b.wide
  %reduced = urem i1 %count, 1
  %shift = zext i1 %reduced to i2
  %wide.left = shl i2 %concatenated, %shift
  %left.high = lshr i2 %wide.left, 1
  %expected.left = trunc i2 %left.high to i1
  %wide.right = lshr i2 %concatenated, %shift
  %expected.right = trunc i2 %wide.right to i1
  %actual.left = call i1 @vm_funnel_left1(i1 %a, i1 %b, i1 %count)
  %actual.right = call i1 @vm_funnel_right1(i1 %a, i1 %b, i1 %count)
  %bad.left = icmp ne i1 %actual.left, %expected.left
  %bad.right = icmp ne i1 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  ret i1 %bad.funnel
}

define i1 @check3(i3 %a, i3 %b, i3 %count) {
entry:
  %a.wide = zext i3 %a to i6
  %b.wide = zext i3 %b to i6
  %high = shl i6 %a.wide, 3
  %concatenated = or i6 %high, %b.wide
  %reduced = urem i3 %count, 3
  %shift = zext i3 %reduced to i6
  %wide.left = shl i6 %concatenated, %shift
  %left.high = lshr i6 %wide.left, 3
  %expected.left = trunc i6 %left.high to i3
  %wide.right = lshr i6 %concatenated, %shift
  %expected.right = trunc i6 %wide.right to i3
  %actual.left = call i3 @vm_funnel_left3(i3 %a, i3 %b, i3 %count)
  %actual.right = call i3 @vm_funnel_right3(i3 %a, i3 %b, i3 %count)
  %bad.left = icmp ne i3 %actual.left, %expected.left
  %bad.right = icmp ne i3 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  ret i1 %bad.funnel
}

define i1 @check8(i8 %a, i8 %b, i8 %count) {
entry:
  %a.wide = zext i8 %a to i16
  %b.wide = zext i8 %b to i16
  %high = shl i16 %a.wide, 8
  %concatenated = or i16 %high, %b.wide
  %reduced = urem i8 %count, 8
  %shift = zext i8 %reduced to i16
  %wide.left = shl i16 %concatenated, %shift
  %left.high = lshr i16 %wide.left, 8
  %expected.left = trunc i16 %left.high to i8
  %wide.right = lshr i16 %concatenated, %shift
  %expected.right = trunc i16 %wide.right to i8
  %actual.left = call i8 @vm_funnel_left8(i8 %a, i8 %b, i8 %count)
  %actual.right = call i8 @vm_funnel_right8(i8 %a, i8 %b, i8 %count)
  %bad.left = icmp ne i8 %actual.left, %expected.left
  %bad.right = icmp ne i8 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  ret i1 %bad.funnel
}

define i1 @check64(i64 %a, i64 %b, i64 %count) {
entry:
  %a.wide = zext i64 %a to i128
  %b.wide = zext i64 %b to i128
  %high = shl i128 %a.wide, 64
  %concatenated = or i128 %high, %b.wide
  %reduced = urem i64 %count, 64
  %shift = zext i64 %reduced to i128
  %wide.left = shl i128 %concatenated, %shift
  %left.high = lshr i128 %wide.left, 64
  %expected.left = trunc i128 %left.high to i64
  %wide.right = lshr i128 %concatenated, %shift
  %expected.right = trunc i128 %wide.right to i64
  %actual.left = call i64 @vm_funnel_left64(i64 %a, i64 %b, i64 %count)
  %actual.right = call i64 @vm_funnel_right64(i64 %a, i64 %b, i64 %count)
  %bad.left = icmp ne i64 %actual.left, %expected.left
  %bad.right = icmp ne i64 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  %aa = or i128 %high, %a.wide
  %bb.high = shl i128 %b.wide, 64
  %bb = or i128 %bb.high, %b.wide
  %aa.left = shl i128 %aa, %shift
  %aa.left.high = lshr i128 %aa.left, 64
  %expected.rotate.left = trunc i128 %aa.left.high to i64
  %bb.right = lshr i128 %bb, %shift
  %expected.rotate.right = trunc i128 %bb.right to i64
  %actual.rotate.left = call i64 @vm_funnel_rotate_left64(i64 %a, i64 %count)
  %actual.rotate.right = call i64 @vm_funnel_rotate_right64(i64 %b, i64 %count)
  %bad.rotate.left = icmp ne i64 %actual.rotate.left, %expected.rotate.left
  %bad.rotate.right = icmp ne i64 %actual.rotate.right, %expected.rotate.right
  %bad.rotate = or i1 %bad.rotate.left, %bad.rotate.right
  %bad = or i1 %bad.funnel, %bad.rotate
  ret i1 %bad
}

define i1 @check127(i127 %a, i127 %b, i127 %count) {
entry:
  %a.wide = zext i127 %a to i254
  %b.wide = zext i127 %b to i254
  %high = shl i254 %a.wide, 127
  %concatenated = or i254 %high, %b.wide
  %reduced = urem i127 %count, 127
  %shift = zext i127 %reduced to i254
  %wide.left = shl i254 %concatenated, %shift
  %left.high = lshr i254 %wide.left, 127
  %expected.left = trunc i254 %left.high to i127
  %wide.right = lshr i254 %concatenated, %shift
  %expected.right = trunc i254 %wide.right to i127
  %actual.left = call i127 @vm_funnel_left127(i127 %a, i127 %b, i127 %count)
  %actual.right = call i127 @vm_funnel_right127(i127 %a, i127 %b, i127 %count)
  %bad.left = icmp ne i127 %actual.left, %expected.left
  %bad.right = icmp ne i127 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  ret i1 %bad.funnel
}

define i1 @check128(i128 %a, i128 %b, i128 %count) {
entry:
  %a.wide = zext i128 %a to i256
  %b.wide = zext i128 %b to i256
  %high = shl i256 %a.wide, 128
  %concatenated = or i256 %high, %b.wide
  %reduced = urem i128 %count, 128
  %shift = zext i128 %reduced to i256
  %wide.left = shl i256 %concatenated, %shift
  %left.high = lshr i256 %wide.left, 128
  %expected.left = trunc i256 %left.high to i128
  %wide.right = lshr i256 %concatenated, %shift
  %expected.right = trunc i256 %wide.right to i128
  %actual.left = call i128 @vm_funnel_left128(i128 %a, i128 %b, i128 %count)
  %actual.right = call i128 @vm_funnel_right128(i128 %a, i128 %b, i128 %count)
  %bad.left = icmp ne i128 %actual.left, %expected.left
  %bad.right = icmp ne i128 %actual.right, %expected.right
  %bad.funnel = or i1 %bad.left, %bad.right
  ret i1 %bad.funnel
}

; Exhaust every operand/count combination for i1 and i3, and every unsigned
; i8 count with distinct values. This includes modulo-zero boundaries where
; fshl returns a but fshr returns b, not their bitwise OR.
define i1 @check_narrow() {
entry:
  br label %one

one:
  %one.index = phi i16 [ 0, %entry ], [ %one.next, %one ]
  %one.errors = phi i1 [ false, %entry ], [ %one.bad, %one ]
  %one.a = trunc i16 %one.index to i1
  %one.b.bits = lshr i16 %one.index, 1
  %one.b = trunc i16 %one.b.bits to i1
  %one.count.bits = lshr i16 %one.index, 2
  %one.count = trunc i16 %one.count.bits to i1
  %one.check = call i1 @check1(i1 %one.a, i1 %one.b, i1 %one.count)
  %one.bad = or i1 %one.errors, %one.check
  %one.next = add i16 %one.index, 1
  %one.done = icmp eq i16 %one.next, 8
  br i1 %one.done, label %three, label %one

three:
  %three.index = phi i16 [ 0, %one ], [ %three.next, %three ]
  %three.errors = phi i1 [ %one.bad, %one ], [ %three.bad, %three ]
  %three.a = trunc i16 %three.index to i3
  %three.b.bits = lshr i16 %three.index, 3
  %three.b = trunc i16 %three.b.bits to i3
  %three.count.bits = lshr i16 %three.index, 6
  %three.count = trunc i16 %three.count.bits to i3
  %three.check = call i1 @check3(i3 %three.a, i3 %three.b, i3 %three.count)
  %three.bad = or i1 %three.errors, %three.check
  %three.next = add i16 %three.index, 1
  %three.done = icmp eq i16 %three.next, 512
  br i1 %three.done, label %eight, label %three

eight:
  %eight.index = phi i16 [ 0, %three ], [ %eight.next, %eight ]
  %eight.errors = phi i1 [ %three.bad, %three ], [ %eight.bad, %eight ]
  %eight.count = trunc i16 %eight.index to i8
  %eight.check = call i1 @check8(i8 181, i8 106, i8 %eight.count)
  %eight.bad = or i1 %eight.errors, %eight.check
  %eight.next = add i16 %eight.index, 1
  %eight.done = icmp eq i16 %eight.next, 256
  br i1 %eight.done, label %exit, label %eight

exit:
  ret i1 %eight.bad
}

; Each wide type covers 0, 1, width-1, width, width+1 and large unsigned
; counts. The i127 counts above bit 64 catch truncation before modulo.
define i32 @main() {
entry:
  %bad.narrow = call i1 @check_narrow()
  %check.0 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 0)
  %bad.0 = or i1 %bad.narrow, %check.0
  %check.1 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 1)
  %bad.1 = or i1 %bad.0, %check.1
  %check.2 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 63)
  %bad.2 = or i1 %bad.1, %check.2
  %check.3 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 64)
  %bad.3 = or i1 %bad.2, %check.3
  %check.4 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 65)
  %bad.4 = or i1 %bad.3, %check.4
  %check.5 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 18446744073709551615)
  %bad.5 = or i1 %bad.4, %check.5
  %check.6 = call i1 @check64(i64 81985529216486895, i64 18364758544493064720, i64 4294967303)
  %bad.6 = or i1 %bad.5, %check.6
  %check.7 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 0)
  %bad.7 = or i1 %bad.6, %check.7
  %check.8 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 1)
  %bad.8 = or i1 %bad.7, %check.8
  %check.9 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 126)
  %bad.9 = or i1 %bad.8, %check.9
  %check.10 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 127)
  %bad.10 = or i1 %bad.9, %check.10
  %check.11 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 128)
  %bad.11 = or i1 %bad.10, %check.11
  %check.12 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 1267650600228229401496703205377)
  %bad.12 = or i1 %bad.11, %check.12
  %check.13 = call i1 @check127(i127 85070591730234615865925637387158539759, i127 42535295865117307951286584473464091152, i127 170141183460469231731687303715884105727)
  %bad.13 = or i1 %bad.12, %check.13
  %check.14 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 0)
  %bad.14 = or i1 %bad.13, %check.14
  %check.15 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 1)
  %bad.15 = or i1 %bad.14, %check.15
  %check.16 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 127)
  %bad.16 = or i1 %bad.15, %check.16
  %check.17 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 128)
  %bad.17 = or i1 %bad.16, %check.17
  %check.18 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 129)
  %bad.18 = or i1 %bad.17, %check.18
  %check.19 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 1267650600228229401496703205377)
  %bad.19 = or i1 %bad.18, %check.19
  %check.20 = call i1 @check128(i128 170141183460469231731769289245100592623, i128 85070591730234615884208410402435117584, i128 340282366920938463463374607431768211455)
  %bad.20 = or i1 %bad.19, %check.20
  %code = zext i1 %bad.20 to i32
  ret i32 %code
}

; ADMIT-DAG: vm_funnel_left1|candidate
; ADMIT-DAG: vm_funnel_right1|candidate
; ADMIT-DAG: vm_funnel_left3|candidate
; ADMIT-DAG: vm_funnel_right3|candidate
; ADMIT-DAG: vm_funnel_left8|candidate
; ADMIT-DAG: vm_funnel_right8|candidate
; ADMIT-DAG: vm_funnel_left64|candidate
; ADMIT-DAG: vm_funnel_right64|candidate
; ADMIT-DAG: vm_funnel_left127|candidate
; ADMIT-DAG: vm_funnel_right127|candidate
; ADMIT-DAG: vm_funnel_left128|candidate
; ADMIT-DAG: vm_funnel_right128|candidate
; ADMIT-DAG: vm_funnel_rotate_left64|candidate
; ADMIT-DAG: vm_funnel_rotate_right64|candidate
; ADMIT-DAG: vm_funnel_vector_left|not_candidate
; ADMIT-DAG: vm_funnel_vector_right|not_candidate

; BUDGET-DAG: vm_funnel_left8|not_candidate
; BUDGET-DAG: vm_funnel_right8|not_candidate
; BUDGET-DAG: vm_funnel_left127|not_candidate
; BUDGET-DAG: vm_funnel_right128|not_candidate
; BUDGET-DAG: vm_funnel_rotate_left64|not_candidate

; VM-LABEL: define i1 @vm_funnel_left1(
; VM: entry.obf.vm.wrapper:
; VM: call i1 %vm_funnel_left1.obf.wrapper.indirect
; VM-LABEL: define i1 @vm_funnel_right1(
; VM: entry.obf.vm.wrapper:
; VM: call i1 %vm_funnel_right1.obf.wrapper.indirect
; VM-LABEL: define i3 @vm_funnel_left3(
; VM: entry.obf.vm.wrapper:
; VM: call i3 %vm_funnel_left3.obf.wrapper.indirect
; VM-LABEL: define i3 @vm_funnel_right3(
; VM: entry.obf.vm.wrapper:
; VM: call i3 %vm_funnel_right3.obf.wrapper.indirect
; VM-LABEL: define i8 @vm_funnel_left8(
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_left8.obf.wrapper.indirect
; VM-LABEL: define i8 @vm_funnel_right8(
; VM: entry.obf.vm.wrapper:
; VM: call i8 %vm_funnel_right8.obf.wrapper.indirect
; VM-LABEL: define i64 @vm_funnel_left64(
; VM: entry.obf.vm.wrapper:
; VM: call i64 %vm_funnel_left64.obf.wrapper.indirect
; VM-LABEL: define i64 @vm_funnel_right64(
; VM: entry.obf.vm.wrapper:
; VM: call i64 %vm_funnel_right64.obf.wrapper.indirect
; VM-LABEL: define i127 @vm_funnel_left127(
; VM: entry.obf.vm.wrapper:
; VM: call i127 %vm_funnel_left127.obf.wrapper.indirect
; VM-LABEL: define i127 @vm_funnel_right127(
; VM: entry.obf.vm.wrapper:
; VM: call i127 %vm_funnel_right127.obf.wrapper.indirect
; VM-LABEL: define i128 @vm_funnel_left128(
; VM: entry.obf.vm.wrapper:
; VM: call i128 %vm_funnel_left128.obf.wrapper.indirect
; VM-LABEL: define i128 @vm_funnel_right128(
; VM: entry.obf.vm.wrapper:
; VM: call i128 %vm_funnel_right128.obf.wrapper.indirect
; VM-LABEL: define i64 @vm_funnel_rotate_left64(
; VM: entry.obf.vm.wrapper:
; VM: call i64 %vm_funnel_rotate_left64.obf.wrapper.indirect
; VM-LABEL: define i64 @vm_funnel_rotate_right64(
; VM: entry.obf.vm.wrapper:
; VM: call i64 %vm_funnel_rotate_right64.obf.wrapper.indirect
; VM-LABEL: define <2 x i8> @vm_funnel_vector_left(
; VM: call <2 x i8> @llvm.fshl.v2i8
; VM-LABEL: define <2 x i8> @vm_funnel_vector_right(
; VM: call <2 x i8> @llvm.fshr.v2i8
