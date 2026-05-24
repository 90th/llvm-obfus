; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/runtime-abi-entropy-release.yaml -passes='obf-constant-encode,obf-artifact-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/runtime-abi-entropy-release.yaml -passes='obf-constant-encode,obf-artifact-cleanup' -disable-output %s

define i32 @mix(i32 %x) {
entry:
  %a = add i32 %x, 42
  %b = xor i32 %a, 7
  ret i32 %b
}

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK: call { i64, i64 } @rt_core_ep{{[0-4]}}()
; CHECK-NOT: __obf_entropy_anchor
; CHECK-NOT: __obf_load_entropy_pair
; CHECK-NOT: release marker stripping failure: external
