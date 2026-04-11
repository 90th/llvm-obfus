; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @value() {
entry:
  ret i32 42
}

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @first_char(ptr @.secret)
  %value = call i32 @value()
  %folded = call i32 @fold_value(i32 %value)
  %ok1 = icmp eq i32 %result, 0
  %ok2 = icmp eq i32 %folded, 4723
  %ok = and i1 %ok1, %ok2
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: @.secret = private unnamed_addr global [7 x i8]
; CHECK: @__obf_decoded__secret = internal global i1 false
; CHECK-LABEL: define i32 @value()
; CHECK: ret i32 42
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: entry.obf.vm:
; CHECK: dispatch.obf.vm:
; CHECK-NOT: fold_value.obf.split
; CHECK-LABEL: define i32 @main()
; CHECK: %0 = call ptr @__obf_family_
; CHECK: br label %entry.obf.split
; CHECK: define internal ptr @__obf_family_
