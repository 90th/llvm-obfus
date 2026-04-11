; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @fold_value(i32 0)
  %ok = icmp eq i32 %result, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: @__obf_vm_target_fold_value = private global ptr @fold_value
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: entry.obf.vm:
; CHECK: %obf.vm.pc = alloca i32
; CHECK: br label %dispatch.obf.vm
; CHECK: dispatch.obf.vm:
; CHECK: switch i32 %obf.vm.pc.load
; CHECK: trap.obf.vm:
; CHECK: call void @llvm.trap()
; CHECK: %obf.vm.const = xor i32
; CHECK-LABEL: define i32 @main()
; CHECK: %fold_value.obf.indirect = load ptr, ptr @__obf_vm_target_fold_value
; CHECK: call i32 %fold_value.obf.indirect(i32 0)
