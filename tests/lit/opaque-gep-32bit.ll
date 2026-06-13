; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep.yaml -passes=obf-opaque-gep -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/opaque-gep.yaml -passes=obf-opaque-gep -S %s -o - | %opt -passes=verify -disable-output

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

; CHECK-LABEL: define i32 @read_field32(ptr %p)
; CHECK: %obf.gep.base = ptrtoint ptr %p to i32
; CHECK: %field = inttoptr i32 %obf.gep.addr to ptr
