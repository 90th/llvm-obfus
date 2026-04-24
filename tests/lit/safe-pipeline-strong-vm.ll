; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @strong_vm_fold(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @strong_vm_fold(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @[[VMBC:_[0-9a-f]+]] = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @[[VMRETKEY:_[0-9a-f]+]] = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @[[VMPTRCONST:_[0-9a-f]+]] = private unnamed_addr constant ptr @[[VMBC]]
; CHECK-DAG: @[[VMTARGET:_[0-9a-f]+]] = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @[[VMTARGETSEED:_[0-9a-f]+]] = private global i64 0
; CHECK-DAG: @[[VMKEY:_[0-9a-f]+]] = private global i64 {{-?[0-9]+}}
; CHECK-NOT: @__obf_vm_
; CHECK-NOT: !dbg
; CHECK-NOT: %obf.
; CHECK-LABEL: define i32 @strong_vm_fold(i32
; CHECK: load i64, ptr @[[VMTARGET]]
; CHECK: load i64, ptr @[[VMKEY]]
; CHECK: load i64, ptr @[[VMTARGETSEED]]
; CHECK: inttoptr i64
; CHECK: call i32 %{{[^ ]+}}(i32 %0, i64 %{{[^)]+}})
; CHECK: load i64, ptr @[[VMRETKEY]]
; CHECK-LABEL: define i32 @main()
; CHECK: load i64, ptr @[[VMTARGET]]
; CHECK: store i64 %{{[^,]+}}, ptr @[[VMTARGET]]
; CHECK: load i64, ptr @[[VMKEY]]
; CHECK: call i32 %{{[^ ]+}}(i32 0, i64 %{{[^)]+}})
; CHECK: load i64, ptr @[[VMRETKEY]]
; CHECK: define internal i32 @[[VMIMPL:_[0-9a-f]+]](i32
; CHECK: load ptr, ptr @[[VMPTRCONST]]
; CHECK: indirectbr ptr
