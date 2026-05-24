; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/artifact-cleanup-release.yaml -passes=obf-artifact-cleanup -S %s -o - | %FileCheck %s

@__obf_str_blob = internal global i8 7
@plain_local = internal global i8 9

define internal i32 @__obf_vm_helper(i32 %value) {
entry:
  %load = load i8, ptr @__obf_str_blob
  %wide = zext i8 %load to i32
  %sum = add i32 %value, %wide
  ret i32 %sum
}

define internal i32 @plain_local_fn(i32 %value) {
entry:
  %call = call i32 @__obf_vm_helper(i32 %value)
  ret i32 %call
}

define i32 @main() {
entry:
  %call = call i32 @plain_local_fn(i32 4)
  ret i32 %call
}

; CHECK-DAG: @[[BLOB:_[0-9a-f]+]] = internal global i8 7
; CHECK-DAG: @plain_local = internal global i8 9
; CHECK: define internal i32 @[[HELPER:_[0-9a-f]+]](i32
; CHECK: load i8, ptr @[[BLOB]]
; CHECK: zext i8
; CHECK: add i32
; CHECK-LABEL: define internal i32 @plain_local_fn(i32
; CHECK: call i32 @[[HELPER]](i32 %0)
; CHECK-LABEL: define i32 @main()
; CHECK: call i32 @plain_local_fn(i32 4)
; CHECK-NOT: __obf_
; CHECK-NOT: obf.
