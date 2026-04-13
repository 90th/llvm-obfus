; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep.yaml -passes=obf-opaque-gep -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep.yaml -passes=obf-opaque-gep -S %s -o %t
; RUN: %lli %t

target datalayout = "e-m:e-p:64:64-i64:64-n8:16:32:64-S128"

%Pair = type { i32, i64 }

@glob = global %Pair { i32 7, i64 99 }

define i64 @read_field(ptr %p) {
entry:
  %field = getelementptr inbounds %Pair, ptr %p, i64 0, i32 1
  %val = load i64, ptr %field, align 8
  ret i64 %val
}

define i64 @read_global_field() {
entry:
  %val = load i64, ptr getelementptr inbounds (%Pair, ptr @glob, i64 0, i32 1), align 8
  ret i64 %val
}

define i64 @phi_field(i1 %cond, ptr %a, ptr %b) {
entry:
  br i1 %cond, label %left, label %right

left:
  %left.field = getelementptr inbounds %Pair, ptr %a, i64 0, i32 1
  br label %merge

right:
  %right.field = getelementptr inbounds %Pair, ptr %b, i64 0, i32 1
  br label %merge

merge:
  %field = phi ptr [ %left.field, %left ], [ %right.field, %right ]
  %val = load i64, ptr %field, align 8
  ret i64 %val
}

define i32 @main() {
entry:
  %stack = alloca %Pair, align 8
  %field0 = getelementptr inbounds %Pair, ptr %stack, i64 0, i32 0
  store i32 1, ptr %field0, align 4
  %field1 = getelementptr inbounds %Pair, ptr %stack, i64 0, i32 1
  store i64 99, ptr %field1, align 8
  %a = call i64 @read_field(ptr %stack)
  %b = call i64 @read_global_field()
  %c = call i64 @phi_field(i1 true, ptr %stack, ptr @glob)
  %ok1 = icmp eq i64 %a, 99
  %ok2 = icmp eq i64 %b, 99
  %ok3 = icmp eq i64 %c, 99
  %ok12 = and i1 %ok1, %ok2
  %ok = and i1 %ok12, %ok3
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK-NOT: getelementptr
; CHECK-LABEL: define i64 @read_field(ptr %p)
; CHECK: %obf.gep.base = ptrtoint ptr %p to i64
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.gep.addr =
; CHECK: %field = inttoptr i64 %obf.gep.addr to ptr
; CHECK-LABEL: define i64 @read_global_field()
; CHECK: %obf.gep.base = ptrtoint ptr @glob to i64
; CHECK: inttoptr i64 %obf.gep.addr to ptr
; CHECK-LABEL: define i64 @phi_field(i1 %cond, ptr %a, ptr %b)
; CHECK: left:
; CHECK: ptrtoint ptr %a to i64
; CHECK: br label %merge
; CHECK: right:
; CHECK: ptrtoint ptr %b to i64
; CHECK: br label %merge
; CHECK: merge:
; CHECK: %field = phi ptr
