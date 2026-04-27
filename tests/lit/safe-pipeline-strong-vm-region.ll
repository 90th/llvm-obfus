; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-region.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-region.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=SAFE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm-region.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @strong_vm_region(ptr %out, i32 %x) {
entry:
  %scratch = alloca i32
  call void @sink_ext(ptr %out)
  store i32 0, ptr %scratch
  br label %logic

logic:
  %gt = icmp sgt i32 %x, 0
  br i1 %gt, label %left, label %right

left:
  %a = add i32 %x, 7
  br label %merge

right:
  %b = sub i32 7, %x
  br label %merge

merge:
  %v = phi i32 [ %a, %left ], [ %b, %right ]
  %cmp = icmp slt i32 %v, 10
  br i1 %cmp, label %small, label %large

small:
  %small.v = add i32 %v, 3
  ret i32 %small.v

large:
  %large.v = sub i32 %v, 1
  ret i32 %large.v
}

define void @sink_ext(ptr %p) {
entry:
  ret void
}

define i32 @strong_vm_two_regions(ptr %out, i32 %x, i32 %y) {
entry:
  %scratch = alloca i32
  call void @sink_ext(ptr %out)
  store i32 0, ptr %scratch
  br label %r1.head

r1.head:
  %xpos = icmp sgt i32 %x, 0
  br i1 %xpos, label %r1.left, label %r1.right

r1.left:
  %lhs = add i32 %x, 7
  br label %r1.merge

r1.right:
  %rhs = sub i32 7, %x
  br label %r1.merge

r1.merge:
  %v = phi i32 [ %lhs, %r1.left ], [ %rhs, %r1.right ]
  %ypos = icmp sgt i32 %y, 0
  br i1 %ypos, label %r2.left, label %r2.right

r2.left:
  %sum = add i32 %v, %y
  br label %r2.merge

r2.right:
  %diff = sub i32 %v, %y
  br label %r2.merge

r2.merge:
  %w = phi i32 [ %sum, %r2.left ], [ %diff, %r2.right ]
  ret i32 %w
}

define i32 @main() {
entry:
  %slot = alloca i32
  %pos = call i32 @strong_vm_region(ptr %slot, i32 5)
  %neg = call i32 @strong_vm_region(ptr %slot, i32 -2)
  %r0 = call i32 @strong_vm_two_regions(ptr %slot, i32 5, i32 3)
  %r1 = call i32 @strong_vm_two_regions(ptr %slot, i32 -2, i32 -4)
  %sum0 = add i32 %pos, %neg
  %sum1 = add i32 %sum0, %r0
  %sum = add i32 %sum1, %r1
  %ok = icmp eq i32 %sum, 51
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; VM-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; VM-DAG: @__obf_vm_ptrconst_{{[0-9A-F]+}} = private unnamed_addr constant ptr @__obf_vm_bc_i_{{[A-Za-z0-9_]+}}
; VM-DAG: @__obf_vm_s_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}} 0
; VM-LABEL: define i32 @strong_vm_region(ptr %out, i32 %x)
; VM: call void @__obf_vm_g_{{[A-Za-z0-9_]+}}(i32 %x, ptr %v.ce.loc)
; VM-LABEL: define i32 @strong_vm_two_regions(ptr %out, i32 %x, i32 %y)
; VM: call void @__obf_vm_g_{{[A-Za-z0-9_]+}}(i32 %x, ptr %v.ce.loc)
; VM: call void @__obf_vm_g_{{[A-Za-z0-9_]+}}(i32 %{{[^,]+}}, i32 %{{[^,]+}}, ptr %w.ce.loc)
; VM-LABEL: define internal void @__obf_vm_g_{{[A-Za-z0-9_]+}}(i32 %x, ptr %v.ce.out) {
; VM: load i64, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; VM: load i64, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; VM: call void %{{[^ ]+}}(i32 %x, ptr %v.ce.ce.loc, i64
; VM-LABEL: define dso_local void @__obf_vm_g_{{[A-Za-z0-9_]+}}(i32 %x, ptr %v.ce.ce.out) {
; VM: load i64, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; VM: load i64, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; VM: call void %{{[^ ]+}}(i32 %x, ptr %v.ce.ce.out, i64
; VM-LABEL: define internal void @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, ptr %v.ce.ce.out, i64 %obf.hidden_token) #{{[0-9]+}} {
; VM: %obf.vm.ptr.const = load ptr, ptr @__obf_vm_ptrconst_{{[0-9A-F]+}}
; VM: indirectbr ptr
; SAFE-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; SAFE-LABEL: define i32 @strong_vm_region(ptr
; SAFE: load i64, ptr @__obf_entropy_anchor
; SAFE-LABEL: define i32 @strong_vm_two_regions(ptr
; SAFE: call void @{{_[0-9a-f]+}}(i32 %{{[^,]+}}, ptr %{{[^)]+}})
; SAFE: call void @{{_[0-9a-f]+}}(i32 %{{[^,]+}}, i32 %{{[^,]+}}, ptr %{{[^)]+}})
; SAFE: define internal void @{{_[0-9a-f]+}}(i32 %0, ptr %1) {
; SAFE: call void %{{[^ ]+}}(i32 %0, ptr %{{[^,]+}}, i64 %{{[^)]+}})
; SAFE: define internal void @{{_[0-9a-f]+}}(i32 %0, ptr %1, i64 %2)
; SAFE: indirectbr ptr
; SAFE: define internal void @{{_[0-9a-f]+}}(i32 %0, i32 %1, ptr %2) {
; SAFE: call void %{{[^ ]+}}(i32 %1, i32 %0, ptr %{{[^,]+}}, i64 %{{[^)]+}})
; SAFE: define internal void @{{_[0-9a-f]+}}(i32 %0, i32 %1, ptr %2, i64 %3)
; SAFE: indirectbr ptr
