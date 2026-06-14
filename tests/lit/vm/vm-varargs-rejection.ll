; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-varargs-rejection.yaml -passes=obf-feature-report -disable-output %s | jq -r '.transforms[] | select(.pass == "vm") | [.target_name, .status, .detail] | join("|")' | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-varargs-rejection.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=IR --implicit-check-not='__obf_vm_'

declare void @llvm.va_start(ptr)
declare void @llvm.va_end(ptr)

define i32 @plain_vm_varargs(i32 %x, ...) {
entry:
  ret i32 %x
}

define i32 @vastart_vm_varargs(i32 %x, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  call void @llvm.va_end(ptr %list)
  ret i32 %x
}

define i32 @plain_strong_vm_varargs(i32 %x, ...) {
entry:
  ret i32 %x
}

define i32 @vastart_strong_vm_varargs(i32 %x, ...) {
entry:
  %list = alloca ptr, align 8
  call void @llvm.va_start(ptr %list)
  call void @llvm.va_end(ptr %list)
  ret i32 %x
}

define i32 @main() {
entry:
  ret i32 0
}

; REPORT-DAG: plain_vm_varargs|skipped|varargs unsupported by VM lowering
; REPORT-DAG: vastart_vm_varargs|skipped|varargs unsupported by VM lowering
; REPORT-DAG: plain_strong_vm_varargs|skipped|varargs unsupported by VM lowering
; REPORT-DAG: vastart_strong_vm_varargs|skipped|varargs unsupported by VM lowering

; IR-LABEL: define i32 @plain_vm_varargs(i32 %x, ...)
; IR-LABEL: define i32 @vastart_vm_varargs(i32 %x, ...)
; IR-LABEL: define i32 @plain_strong_vm_varargs(i32 %x, ...)
; IR-LABEL: define i32 @vastart_strong_vm_varargs(i32 %x, ...)
