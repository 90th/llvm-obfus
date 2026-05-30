; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep-scaled.yaml -passes=obf-opaque-gep -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep-scaled.yaml -passes=obf-opaque-gep -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep-scaled.yaml -passes=obf-opaque-gep -S %s -o %t
; RUN: %lli %t

target datalayout = "e-m:e-p:64:64-i64:64-n8:16:32:64-S128"

%Pair = type { i32, i64 }

@pairs = global [3 x %Pair] [%Pair { i32 1, i64 11 },
                             %Pair { i32 2, i64 22 },
                             %Pair { i32 3, i64 33 }]

define i64 @read_index(i32 %idx) {
entry:
  %base = getelementptr inbounds [3 x %Pair], ptr @pairs, i64 0, i64 0
  %field = getelementptr inbounds %Pair, ptr %base, i32 %idx, i32 1
  %val = load i64, ptr %field, align 8
  ret i64 %val
}

define i32 @main() {
entry:
  %v0 = call i64 @read_index(i32 0)
  %v1 = call i64 @read_index(i32 1)
  %v2 = call i64 @read_index(i32 2)
  %ok0 = icmp eq i64 %v0, 11
  %ok1 = icmp eq i64 %v1, 22
  %ok2 = icmp eq i64 %v2, 33
  %both0 = and i1 %ok0, %ok1
  %both1 = and i1 %both0, %ok2
  %ret = select i1 %both1, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-NOT: getelementptr
; CHECK-LABEL: define i64 @read_index(i32 %idx)
; CHECK: %obf.gep.base = ptrtoint ptr @pairs to i64
; CHECK: %obf.gep.index = sext i32 %idx to i64
; CHECK: %obf.gep.scale.term.shl.0 = shl i64 %obf.gep.index, 4
; CHECK: %obf.gep.scale =
; CHECK: %field = inttoptr i64 %obf.gep.addr{{[0-9]*}} to ptr
