; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/artifact-cleanup-release.yaml -passes=obf-artifact-cleanup -disable-output %s 2>&1 | %FileCheck %s

declare i32 @__obf_get_cfg_state()

define i32 @main() {
entry:
  %0 = call i32 @__obf_get_cfg_state()
  ret i32 %0
}

; CHECK: LLVM ERROR: release marker stripping failure: cfg placeholder __obf_get_cfg_state survived final cleanup
