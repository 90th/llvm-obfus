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

; CHECK: @__obf_vm_target_strong_vm_fold = private global ptr @strong_vm_fold
; CHECK-LABEL: define i32 @strong_vm_fold(i32 %value)
; CHECK: entry.obf.vm:
; CHECK: dispatch.obf.vm:
; CHECK: switch i32 %obf.vm.pc.load
; CHECK: %obf.vm.const = xor i32
; CHECK-LABEL: define i32 @main()
; CHECK: %strong_vm_fold.obf.indirect = load ptr, ptr @__obf_vm_target_strong_vm_fold
; CHECK: call i32 %strong_vm_fold.obf.indirect(i32 0)
