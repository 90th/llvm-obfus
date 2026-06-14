; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-target-cache.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=TARGET
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-seed-resolver.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=SEED
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-normal-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=NORMAL

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

; TARGET: LLVM ERROR: strong_vm invariant violation: target_cache_case emitted target-cache resolver
; SEED: LLVM ERROR: strong_vm invariant violation: seed_case used shared seed resolver
; NORMAL-LABEL: define i32 @target_cache_case
; NORMAL-LABEL: define i32 @seed_case
