; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-lifter-destruction.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s

target triple = "x86_64-unknown-linux-gnu"

define i32 @vm_target(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @vm_target(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-DAG: call void asm sideeffect "cmpq $0, $1; jne 1f; .byte 0x0f; 1:; .byte 0x1f, 0x44, 0x00, 0x00", "r,r,~{cc},~{memory}"
; CHECK-LABEL: define i32 @main()
; CHECK: call i32 %{{[^ ]+}}(i32 0, i64 %{{[^)]+}})
; CHECK: define internal i32 @{{[^ ]+}}(i32
