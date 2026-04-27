; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=PASS --implicit-check-not='@__obf_vm_target_strong_ok' --implicit-check-not='@__obf_vm_seedcase_strong_ok' --implicit-check-not='@__obf_vm_seed_resolve'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-strong-vm-off.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=OFF
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-strong-vm-unvirtualized.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=UNVIRT
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/security-gates-strong-vm-string.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=STRING

@.secret = private unnamed_addr constant [6 x i8] c"hello\00"
@.table = private unnamed_addr constant [1 x ptr] [ptr @.secret]

define i32 @strong_ok(i32 %x) {
entry:
  %xor = xor i32 %x, 42
  %sum = add i32 %xor, 7
  ret i32 %sum
}

define i32 @unsupported_alloca(i32 %x) {
entry:
  %slot = alloca i32, align 4
  store i32 %x, ptr %slot, align 4
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}

define i32 @string_table_user(i64 %index) {
entry:
  %slot = getelementptr inbounds [1 x ptr], ptr @.table, i64 0, i64 0
  %base = load ptr, ptr %slot, align 8
  %ptr = getelementptr inbounds i8, ptr %base, i64 %index
  %byte = load i8, ptr %ptr, align 1
  %ret = zext i8 %byte to i32
  ret i32 %ret
}

define i32 @main() {
entry:
  %value = call i32 @strong_ok(i32 5)
  %ok = icmp eq i32 %value, 54
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; PASS-LABEL: define i32 @strong_ok(i32 %0)
; PASS: call i32 %{{[^ ]+}}(i32 %0, i64 %{{[^)]+}})
; PASS: define internal i32 @{{_[0-9a-f]+}}(i32 %0, i64 %1)

; OFF: LLVM ERROR: strong_vm invariant violation: function unsupported_alloca was not virtualized

; UNVIRT: LLVM ERROR: strong_vm invariant violation: function unsupported_alloca was not virtualized
; UNVIRT: policy_source=config_rule
; UNVIRT: reason=

; STRING: LLVM ERROR: strong_vm invariant violation: string .secret would remain plaintext
; STRING: owner=__obf_vm_i_{{[A-Za-z0-9_]+}}
