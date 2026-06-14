; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-router-opacity.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-router-opacity.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; verify pr29.5 router opacity shapes: indirect_ptr_forward and decoy_guarded_forward.
; the wrapper must not contain a direct named call to the vm impl.
; CHECK-LABEL: define i32 @router_a(
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @router_b(
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @router_c(
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @router_d(
; CHECK-NOT: call i32 @__obf_vm_i_
; CHECK-LABEL: define i32 @main(

; indirect_ptr_forward: thunk materializes impl pointer via entangled arithmetic.
; decoy_guarded_forward: thunk keeps the guard and trap path, but now calls via an indirect ptr.
; use CHECK-DAG to allow either ordering in the output.
; CHECK-DAG: obf.vm.entry.thunk.iptr
; CHECK-DAG: obf.vm.entry.thunk.decoy.cond
; CHECK-DAG: obf.vm.entry.thunk.decoy.iptr

; the decoy trap path survives and the valid decoy path uses an indirect call.
; CHECK-DAG: obf.vm.entry.thunk.decoy:
; CHECK-DAG: call void @llvm.trap()
; CHECK-DAG: {{%obf\.vm\.entry\.thunk\.decoy\.iptr\.ptr[^ ]* = }}inttoptr i{{[0-9]+}} {{[^ ]+}} to ptr
; CHECK-DAG: {{%obf\.vm\.entry\.thunk\.decoy\.iptr\.call[^ ]* = }}call i32 %{{[^ ]+}}(

; all four router shapes appear (with seed 2, four functions cover all five slots).
; CHECK-DAG: "vm.entry.thunk.shape.indirect"
; CHECK-DAG: "vm.entry.thunk.shape.decoy_indirect"

define i32 @router_a(i32 %x) {
entry:
  %r = add i32 %x, 3
  ret i32 %r
}

define i32 @router_b(i32 %x) {
entry:
  %r = mul i32 %x, 2
  ret i32 %r
}

define i32 @router_c(i32 %x) {
entry:
  %r = sub i32 %x, 1
  ret i32 %r
}

define i32 @router_d(i32 %x) {
entry:
  %r = add i32 %x, 10
  ret i32 %r
}

define i32 @main() {
entry:
  %a = call i32 @router_a(i32 1)
  %b = call i32 @router_b(i32 2)
  %c = call i32 @router_c(i32 3)
  %d = call i32 @router_d(i32 4)
  ret i32 0
}
