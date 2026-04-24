; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-public-obf-symbol.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s

declare void @__obf_vm_impl_fake()

; CHECK: LLVM ERROR: security gate failure: public obfuscator symbol __obf_vm_impl_fake
