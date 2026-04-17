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

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK-DAG: @[[VMBC:_[0-9a-f]+]] = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @[[VMRETKEY:_[0-9a-f]+]] = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @[[VMTARGET:_[0-9a-f]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @[[VMKEY:_[0-9a-f]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-NOT: @__obf_vm_
; CHECK-NOT: @__obf_family_
; CHECK-NOT: @__obf_cached_
; CHECK-NOT: @__obf_decoded_
; CHECK-NOT: !dbg
; CHECK-NOT: %obf.
; CHECK-LABEL: define i32 @value()
; CHECK: load i64, ptr @__obf_entropy_anchor
; CHECK: load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: ret i32
; CHECK-LABEL: define i32 @fold_value(i32
; CHECK: call i32 @[[VMIMPL:_[0-9a-f]+]](i32 %0, i64
; CHECK-LABEL: define i32 @main()
; CHECK: call ptr @[[STRHELPER:_[0-9a-f]+]](ptr
; CHECK: load i{{[0-9]+}}, ptr @[[VMTARGET]]
; CHECK: store i{{[0-9]+}} %{{[^,]+}}, ptr @[[VMTARGET]]
; CHECK: load i{{[0-9]+}}, ptr @[[VMKEY]]
; CHECK: call i32 %{{[0-9]+}}(i32 %{{[0-9]+}}, i64 %{{[0-9]+}})
; CHECK: load i64, ptr @[[VMRETKEY]]
; CHECK: define i32 @[[VMIMPL]](i32
; CHECK: load i8, ptr @[[VMBC]]
; CHECK: indirectbr ptr
; CHECK: define internal ptr @[[STRHELPER]](ptr
