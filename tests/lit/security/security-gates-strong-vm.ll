; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=PASS --implicit-check-not='@__obf_vm_target_strong_ok' --implicit-check-not='@__obf_vm_seedcase_strong_ok' --implicit-check-not='@__obf_vm_seed_resolve'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-eh-pass.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=EH-PASS --implicit-check-not='LLVM ERROR'
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-off.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=OFF
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-unvirtualized.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=UNVIRT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-string.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s --check-prefix=STRING
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-varargs-pass.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=VARARGS-PLAIN
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-varargs-region-pass.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=VARARGS-REGION
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-varargs-loop-pass.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=VARARGS-LOOP
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/security-gates-strong-vm-varargs.yaml -passes=obf-safe-pipeline -disable-output %s 2>&1 | %FileCheck %s --check-prefix=VARARGS

declare void @llvm.va_start(ptr)
declare void @llvm.va_end(ptr)
declare i32 @__gxx_personality_v0(...)

@.secret = private unnamed_addr constant [6 x i8] c"hello\00"
@.table = private unnamed_addr constant [1 x ptr] [ptr @.secret]

define i32 @strong_ok(i32 %x) {
entry:
  %xor = xor i32 %x, 42
  %sum = add i32 %xor, 7
  ret i32 %sum
}

define i32 @personality_only(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  %sum = add i32 %x, 9
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

define i32 @has_varargs(i32 %x, ...) {
entry:
  ret i32 %x
}

define i32 @has_varargs_access(i32 %x, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  call void @llvm.va_end(ptr %list)
  ret i32 %x
}

define i32 @has_varargs_region(i1 %flag, i32 %x, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  br label %dispatch

dispatch:
  br i1 %flag, label %then, label %else

then:
  %inc = add i32 %x, 1
  br label %merge

else:
  %dec = sub i32 %x, 1
  br label %merge

merge:
  %result = phi i32 [ %inc, %then ], [ %dec, %else ]
  call void @llvm.va_end(ptr %list)
  ret i32 %result
}

define i32 @has_varargs_loop(i32 %n, i32 %x, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  br label %loop

loop:
  %i = phi i32 [ 0, %entry ], [ %next, %body ]
  %acc = phi i32 [ 0, %entry ], [ %sum, %body ]
  %cond = icmp slt i32 %i, %n
  br i1 %cond, label %body, label %exit

body:
  %sum = add i32 %acc, %x
  %next = add i32 %i, 1
  br label %loop

exit:
  call void @llvm.va_end(ptr %list)
  ret i32 %acc
}

; PASS-LABEL: define i32 @strong_ok(i32 %0)
; PASS: call i32 %{{[^ ]+}}(i32 %0, i64 %{{[^)]+}})
; PASS: define internal i32 @{{_[0-9a-f]+}}(i32 %0, i64 %1)

; EH-PASS-LABEL: define i32 @personality_only(i32 %0)
; EH-PASS: call i32 %{{[^ ]+}}(i32 %0, i64 %{{[^)]+}})
; EH-PASS: define internal i32 @{{_[0-9a-f]+}}(i32 %0, i64 %1) {{.*}} personality ptr @__gxx_personality_v0

; OFF: LLVM ERROR: strong_vm invariant violation: function unsupported_alloca was not virtualized

; UNVIRT: LLVM ERROR: strong_vm invariant violation: function unsupported_alloca was not virtualized
; UNVIRT: policy_source=config_rule
; UNVIRT: reason=

; STRING-NOT: LLVM ERROR: strong_vm invariant violation: string .secret would remain plaintext
; STRING: private unnamed_addr global [6 x i8] zeroinitializer
; STRING: private unnamed_addr constant [1 x ptr] [ptr
; STRING: define internal void @{{.*}}() {
; STRING: call ptr @rt_core_sd1(

; VARARGS-PLAIN: LLVM ERROR: strong_vm invariant violation: function has_varargs was not virtualized
; VARARGS-PLAIN: reason_tag=varargs_unsupported

; VARARGS-REGION: LLVM ERROR: strong_vm invariant violation: function has_varargs_region was not virtualized
; VARARGS-REGION: reason_tag=varargs_unsupported

; VARARGS-LOOP: LLVM ERROR: strong_vm invariant violation: function has_varargs_loop was not virtualized
; VARARGS-LOOP: reason_tag=varargs_unsupported

; VARARGS: LLVM ERROR: strong_vm invariant violation: function has_varargs_access was not virtualized
; VARARGS: reason_tag=varargs_unsupported
