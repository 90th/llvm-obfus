; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-whole-preferred.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-whole-preferred.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @strong_vm_whole_preferred(i32 %x, i32 %y) {
entry:
  %xpos = icmp sgt i32 %x, 0
  br i1 %xpos, label %left, label %right

left:
  %lhs = add i32 %x, 7
  br label %merge

right:
  %rhs = sub i32 7, %x
  br label %merge

merge:
  %v = phi i32 [ %lhs, %left ], [ %rhs, %right ]
  %ypos = icmp sgt i32 %y, 0
  br i1 %ypos, label %plus, label %minus

plus:
  %sum = add i32 %v, %y
  ret i32 %sum

minus:
  %diff = sub i32 %v, %y
  ret i32 %diff
}

define i32 @main() {
entry:
  %a = call i32 @strong_vm_whole_preferred(i32 5, i32 3)
  %b = call i32 @strong_vm_whole_preferred(i32 -2, i32 -4)
  %sum = add i32 %a, %b
  %ok = icmp eq i32 %sum, 28
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-DAG: @[[VMTARGETSEED:_[0-9a-f]+]] = private global i64 0
; CHECK-DAG: @[[VMKEY:_[0-9a-f]+]] = private global i64 {{-?[0-9]+}}
; CHECK-NOT: __obf_vm_region_strong_vm_whole_preferred
; CHECK-LABEL: define i32 @strong_vm_whole_preferred(i32
; CHECK: load i64, ptr @{{_[0-9a-f]+}}
; CHECK: load i64, ptr @{{_[0-9a-f]+}}
; CHECK: inttoptr i64
; CHECK: call i32 %{{[^ ]+}}(i32 %{{[^,]+}}, i32 %{{[^,]+}}, i64 %{{[^)]+}})
; CHECK-LABEL: define i32 @main()
; CHECK: call i32 %{{[^ ]+}}(i32 5, i32 3, i64 %{{[^)]+}})
; CHECK: call i32 %{{[^ ]+}}(i32 -2, i32 -4, i64 %{{[^)]+}})
; CHECK: define internal i32 @[[VMIMPL:_[0-9a-f]+]](i32
; CHECK: indirectbr ptr
