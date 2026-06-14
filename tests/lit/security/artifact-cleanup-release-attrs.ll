; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/artifact-cleanup-release.yaml -passes=obf-artifact-cleanup -S %s -o - | %FileCheck %s

define internal void @__obf_vm_entry() #0 {
entry:
  ret void
}

define void @plain() #1 {
entry:
  ret void
}

attributes #0 = { nounwind "obf.vm.entry.thunk" "vm.entry.thunk.shape.split" "vm.island.entry" "vm.bytecode.anchor.count.3" }
attributes #1 = { nounwind }

; CHECK-LABEL: define internal void @{{_[0-9a-f]+}}()
; CHECK-SAME: #[[ATTR:[0-9]+]]
; CHECK-LABEL: define void @plain()
; CHECK-SAME: #[[ATTR]]
; CHECK: attributes #[[ATTR]] = { nounwind }
; CHECK-NOT: obf.vm.entry.thunk
; CHECK-NOT: vm.entry.thunk.shape
; CHECK-NOT: vm.island.
; CHECK-NOT: vm.bytecode.anchor.
