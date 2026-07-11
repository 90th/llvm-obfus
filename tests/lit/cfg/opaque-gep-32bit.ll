; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-gep.yaml --obf-seed=1 -passes=obf-opaque-gep -S %s -o %t
; RUN: %FileCheck %s < %t
; RUN: %opt -passes=verify -disable-output %t

target datalayout = "e-m:e-p:32:32-i64:64-n8:16:32-S128"

%Pair32 = type { i32, i32 }

@glob32 = global %Pair32 { i32 7, i32 99 }

define i32 @read_field32(ptr %p) {
entry:
  %field = getelementptr inbounds %Pair32, ptr %p, i32 0, i32 1
  %val = load i32, ptr %field, align 4
  ret i32 %val
}

define i32 @main() {
entry:
  %v = call i32 @read_field32(ptr @glob32)
  %ok = icmp eq i32 %v, 99
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; The multi-index GEP is lowered per dimension on a 32-bit pointer target: the
; base ptrtoint, a struct-field term, a scaled array/pointer term and opaque-zero
; pads are all i32-wide, and the address is rebuilt via inttoptr.
; CHECK-LABEL: define i32 @read_field32(ptr %p)
; CHECK: %obf.gep.base = ptrtoint ptr %p to i32
; CHECK-DAG: %obf.gep.field
; CHECK-DAG: %obf.gep.scale
; CHECK-DAG: %obf.gep.pad
; CHECK: %field = inttoptr i32 %obf.gep.addr to ptr
