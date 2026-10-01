; RUN: %lli %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml -passes='obf-vm,verify' -S %s -o %t.first.ll
; RUN: %FileCheck %s --check-prefix=VM < %t.first.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml -passes='obf-vm,verify' -S %s -o %t.second.ll
; RUN: cmp %t.first.ll %t.second.ll
; RUN: %lli %t.first.ll
; RUN: %opt -passes='instcombine<no-verify-fixpoint>,verify' -S %t.first.ll -o %t.instcombine.ll
; RUN: %lli %t.instcombine.ll
; RUN: %opt -O2 -S %t.first.ll -o %t.o2.ll
; RUN: %lli %t.o2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-mul-shapes.yaml --obf-seed=2 -passes='obf-vm,verify' -S %s -o %t.seed2.ll
; RUN: %FileCheck %s --check-prefix=VM < %t.seed2.ll
; RUN: %lli %t.seed2.ll

; The VM may expand either multiplication or leave a multiply instruction.
; Compare both operations against untransformed reference arithmetic, including
; signed and unsigned wraparound. The Cartesian product also covers zero,
; negative factors, the sign bit, and adjacent overflow boundaries.
@mul_inputs = private constant [18 x i32] [
  i32 0, i32 1, i32 -1, i32 4, i32 5, i32 6, i32 7, i32 -7,
  i32 429496729, i32 429496730, i32 -429496729, i32 -429496730,
  i32 1073741823, i32 1073741824, i32 -1073741824,
  i32 2147483647, i32 -2147483648, i32 -2147483647
]

define i32 @const_mul(i32 %x) {
entry:
  %mul = mul i32 %x, 5
  ret i32 %mul
}

define i32 @var_mul(i32 %x, i32 %y) {
entry:
  %mul = mul i32 %x, %y
  ret i32 %mul
}

define i32 @main() {
entry:
  br label %outer

outer:
  %i = phi i32 [ 0, %entry ], [ %i.next, %next.outer ]
  %x.ptr = getelementptr inbounds [18 x i32], ptr @mul_inputs, i32 0, i32 %i
  %x = load i32, ptr %x.ptr
  %constant = call i32 @const_mul(i32 %x)
  %constant.frozen = freeze i32 %constant
  %constant.expected = mul i32 %x, 5
  %constant.ok = icmp eq i32 %constant.frozen, %constant.expected
  br i1 %constant.ok, label %inner, label %fail

inner:
  %j = phi i32 [ 0, %outer ], [ %j.next, %next.inner ]
  %y.ptr = getelementptr inbounds [18 x i32], ptr @mul_inputs, i32 0, i32 %j
  %y = load i32, ptr %y.ptr
  %variable = call i32 @var_mul(i32 %x, i32 %y)
  %variable.frozen = freeze i32 %variable
  %variable.expected = mul i32 %x, %y
  %variable.ok = icmp eq i32 %variable.frozen, %variable.expected
  br i1 %variable.ok, label %next.inner, label %fail

next.inner:
  %j.next = add nuw i32 %j, 1
  %more.inner = icmp ult i32 %j.next, 18
  br i1 %more.inner, label %inner, label %next.outer

next.outer:
  %i.next = add nuw i32 %i, 1
  %more.outer = icmp ult i32 %i.next, 18
  br i1 %more.outer, label %outer, label %pass

pass:
  ret i32 0

fail:
  ret i32 1
}

; Check emitted protection, not eligibility alone: both public functions must
; enter a generated VM implementation through a direct or indirect call.
; The internal name suffix and multiplication family are deliberately unpinned.
; VM-LABEL: define i32 @const_mul(i32 %x)
; VM: call i32 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(i32 %x, i64 {{[^)]+}})
; VM: ret i32
; VM-LABEL: define i32 @var_mul(i32 %x, i32 %y)
; VM: call i32 {{(@__obf_vm_[ie]_[A-Za-z0-9_]+|%[A-Za-z0-9$._-]+)}}(i32 %x, i32 %y, i64 {{[^)]+}})
; VM: ret i32
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 {{[^,]+}}, i64 {{[^)]+}})
; VM-DAG: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 {{[^,]+}}, i32 {{[^,]+}}, i64 {{[^)]+}})
