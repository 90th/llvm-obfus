; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/runtime-abi-string-auth-release.yaml -passes='obf-string-encode,obf-cfg-state-cleanup,obf-artifact-cleanup' -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/runtime-abi-string-auth-release.yaml -passes='obf-string-encode,obf-cfg-state-cleanup,obf-artifact-cleanup' -disable-output %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/runtime-abi-string-auth-release.yaml -passes='obf-string-encode,obf-cfg-state-cleanup' -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @main() {
entry:
  %result = load i8, ptr @.secret
  %ok = icmp eq i8 %result, 115
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: call ptr @rt_core_sd1
; CHECK-NOT: obf_string_auth_decode_v1
; CHECK-NOT: release marker stripping failure: external
