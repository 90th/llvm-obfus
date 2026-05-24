; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/artifact-cleanup-release.yaml -passes=obf-artifact-cleanup -disable-output %s 2>&1 | %FileCheck %s

define void @obf_public_helper() {
entry:
  ret void
}

; CHECK: LLVM ERROR: release marker stripping failure: external function obf_public_helper contains obf
