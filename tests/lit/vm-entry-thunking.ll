; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunking.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-entry-thunking.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; Wrapper must route through the thunk — NOT call the impl directly
; CHECK-LABEL: define i32 @thunk_target(
; CHECK-NOT: call i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(
; CHECK-LABEL: define i32 @main(

; VM implementation is present in the module
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(

; Entry thunk forwards to the implementation and carries an internal shape marker
; CHECK: define internal i32 @[[THUNK:__obf_vm_e_[A-Za-z0-9_]+]](
; CHECK: obf.vm.entry.thunk:
; CHECK: call i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}({{.*}}, i64 %{{[A-Za-z0-9$._-]+}})
; CHECK: ret i32
; CHECK: "obf.vm.entry.thunk"
; CHECK: "vm.entry.thunk.shape.{{(direct|neutral|split)}}"

define i32 @thunk_target(i32 %x) {
entry:
  %add = add i32 %x, 7
  ret i32 %add
}

define i32 @main() {
entry:
  %r = call i32 @thunk_target(i32 1)
  %ok = icmp eq i32 %r, 8
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
