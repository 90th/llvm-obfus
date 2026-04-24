; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-target-cache.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=TARGET
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-seed-resolver.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=SEED

@__obf_vm_target_target_cache_case = global i64 0

declare i64 @__obf_vm_seedcase_seed_case(i64, i64)

define i32 @target_cache_case(i32 %x) {
entry:
  %sum = add i32 %x, 3
  ret i32 %sum
}

define i32 @seed_case(i32 %x) {
entry:
  %xor = xor i32 %x, 7
  ret i32 %xor
}

; TARGET: LLVM ERROR: security gate failure: target cache global for strong_vm function target_cache_case
; SEED: LLVM ERROR: security gate failure: shared seed resolver case for strong_vm function seed_case
