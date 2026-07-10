; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/runtime-abi-const-pool-release.yaml -passes='obf-constant-encode,obf-artifact-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/runtime-abi-const-pool-release.yaml -passes='obf-constant-encode,obf-artifact-cleanup' -disable-output %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/runtime-abi-const-pool-release.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @repeated(i32 %x) {
entry:
  %a = add i32 %x, 31337
  %b = xor i32 %a, 31337
  %c = add i32 %b, 31337
  ret i32 %c
}

define i32 @main() {
entry:
  %value = call i32 @repeated(i32 5)
  %ok = icmp eq i32 %value, 31344
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: call ptr @rt_core_cpd3
; CHECK-NOT: obf_constant_pool_decode_v1
; CHECK-NOT: obf_constant_pool_decode_v2
; CHECK-NOT: release marker stripping failure: external
