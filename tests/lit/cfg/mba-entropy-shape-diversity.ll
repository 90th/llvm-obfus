; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes='obf-constant-encode,verify' -S %s -o %t.first.ll
; RUN: %FileCheck %s < %t.first.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml -passes='obf-constant-encode,verify' -S %s -o %t.second.ll
; RUN: cmp %t.first.ll %t.second.ll
; RUN: %lli %t.first.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.first.ll -o %t.instcombine.ll
; RUN: %lli %t.instcombine.ll
; RUN: %opt -O2 -S %t.first.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml --obf-seed=2 -passes='obf-constant-encode,verify' -S %s -o %t.seed2.ll
; RUN: %FileCheck %s < %t.seed2.ll
; RUN: %lli %t.seed2.ll

; Entropy mixing, opaque-zero families, and entanglement are selected by seed
; and source path. Whatever the selection, every encoded operation must agree
; with the original arithmetic, including carries and wraparound.
@shape_inputs = private constant [16 x i32] [
  i32 0, i32 1, i32 -1, i32 7, i32 85, i32 -17, i32 1234, i32 -9999,
  i32 65535, i32 65536, i32 1073741824, i32 -1073741824,
  i32 2147473648, i32 2147483630, i32 2147483647, i32 -2147483648
]

define i32 @shape_mix(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %d = add i32 %c, 9999
  ret i32 %d
}

define i32 @main() {
entry:
  br label %loop

loop:
  %index = phi i32 [ 0, %entry ], [ %next, %continue ]
  %input.ptr = getelementptr inbounds [16 x i32], ptr @shape_inputs, i32 0, i32 %index
  %input = load i32, ptr %input.ptr
  %value = call i32 @shape_mix(i32 %input)
  %value.frozen = freeze i32 %value
  %again = call i32 @shape_mix(i32 %input)
  %again.frozen = freeze i32 %again
  %a = add i32 %input, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 1234
  %expected = add i32 %c, 9999
  %value.ok = icmp eq i32 %value.frozen, %expected
  %again.ok = icmp eq i32 %again.frozen, %expected
  %ok = and i1 %value.ok, %again.ok
  br i1 %ok, label %continue, label %fail

continue:
  %next = add nuw i32 %index, 1
  %more = icmp ult i32 %next, 16
  br i1 %more, label %loop, label %pass

pass:
  ret i32 0

fail:
  ret i32 1
}

; Mixing multiple encoded constants must still sample one complete entropy
; pair at function entry. No particular opaque-zero spelling is required.
; CHECK-LABEL: define i32 @shape_mix(i32 %x)
; CHECK: alloca { i64, i64 }
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK-NOT: call {{.*}}@__obf_entropy_thunk_
; CHECK-NOT: call {{.*}}@rt_core_ep
; CHECK: ret i32
