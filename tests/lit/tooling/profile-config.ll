; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-standard.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=STANDARD
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-fortress.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=FORTRESS
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-invalid.yaml -passes=obf-feature-report -disable-output %s 2>&1 | %FileCheck %s --check-prefix=INVALID
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-fortress-public-symbol.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=PUBLIC
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-fast-strong-vm.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRONGVM
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-overrides.yaml -passes=obf-string-encode -S %s -o - | %FileCheck %s --check-prefix=STRINGOVERRIDE --implicit-check-not='@__obf_str_'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-vm-debug-names.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=PREFLIGHT-VM-DEBUG
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-strong-vm-no-public-gate.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=PREFLIGHT-STRONGVM-NOGATE
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-fortress-no-public-gate.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=PREFLIGHT-FORTRESS-NOGATE
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/profile-unsafe-override.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=PREFLIGHT-UNSAFE-OVERRIDE

@__obf_vm_i_public = global i64 0
@.profile_string = private unnamed_addr constant [6 x i8] c"hello\00"

define i32 @profile_accept(i32 %x) {
entry:
  %sum = add i32 %x, 7
  ret i32 %sum
}

define i32 @unsupported_alloca(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}

define i32 @string_user() {
entry:
  %byte = load i8, ptr @.profile_string, align 1
  %ret = zext i8 %byte to i32
  ret i32 %ret
}

; STANDARD: "detail":"config match:profile_accept"
; STANDARD: "level":"strong"
; FORTRESS: "detail":"config match:profile_accept"
; FORTRESS: "level":"strong"
; INVALID: failed to parse config
; PUBLIC: LLVM ERROR: security gate failure: public obfuscator symbol __obf_vm_i_public
; STRONGVM: LLVM ERROR: strong_vm invariant violation: function unsupported_alloca was not virtualized
; STRINGOVERRIDE: @.profile_string = private unnamed_addr constant [6 x i8] c"hello\00"
; PREFLIGHT-VM-DEBUG: security preflight failure: vm/strong_vm config cannot use debug_preserve_generated_names: true
; PREFLIGHT-VM-DEBUG: security.allow_unsafe_config
; PREFLIGHT-STRONGVM-NOGATE: security preflight failure: strong_vm
; PREFLIGHT-STRONGVM-NOGATE: security.allow_unsafe_config
; PREFLIGHT-FORTRESS-NOGATE: security preflight failure: profile fortress
; PREFLIGHT-FORTRESS-NOGATE: security.allow_unsafe_config
; PREFLIGHT-UNSAFE-OVERRIDE: "detail":"config match:profile_accept"
; PREFLIGHT-UNSAFE-OVERRIDE: "level":"strong"
