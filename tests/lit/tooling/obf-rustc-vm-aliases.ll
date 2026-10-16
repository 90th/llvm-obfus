; REQUIRES: system-linux
; RUN: %raw_clang -O0 %s -o %t.baseline
; RUN: %t.baseline
; RUN: env OBF_COVERAGE_REPORT=%t.vm.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-vm-aliases.yaml -passes=obf-safe-pipeline -S %s -o %t.vm.ll
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.vm.json --level vm --target alias_chain --override alias_direct --baseline-ir %s --escaped escaped_storage_alias --escaped escaped_argument_alias --escaped escaped_integer_alias
; RUN: %raw_clang -O0 %t.vm.ll %obf_runtime -o %t.vm
; RUN: %t.vm
; RUN: %llvm_nm --defined-only %t.vm | %FileCheck %s --check-prefix=SYMBOLS --implicit-check-not=__obf
; RUN: env OBF_COVERAGE_REPORT=%t.strong-vm.json %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/obf-rustc-strong-vm-aliases.yaml -passes=obf-safe-pipeline -S %s -o %t.strong-vm.ll
; RUN: %python %S/../Inputs/frontend-vm-contract.py %t.strong-vm.json --level strong_vm --target alias_chain --override alias_direct --baseline-ir %s --escaped escaped_storage_alias --escaped escaped_argument_alias --escaped escaped_integer_alias
; RUN: %raw_clang -O2 %t.strong-vm.ll %obf_runtime -o %t.strong-vm
; RUN: %t.strong-vm
; RUN: %llvm_nm --defined-only %t.strong-vm | %FileCheck %s --check-prefix=SYMBOLS --implicit-check-not=__obf
;
; Direct aliases and alias chains are public entry names, not address escapes.
; Storage, arguments, and integer conversion must keep the address-escape restriction.
; SYMBOLS-DAG: alias_chain
; SYMBOLS-DAG: alias_direct
; SYMBOLS-DAG: escaped_storage_alias
; SYMBOLS-DAG: escaped_argument_alias
; SYMBOLS-DAG: escaped_integer_alias

@alias_chain = alias i32 (i32), ptr @alias_middle
@alias_middle = alias i32 (i32), ptr @alias_target_impl
@alias_direct = alias i32 (i32), ptr @alias_override_impl
@escaped_storage_alias = alias i32 (i32), ptr @escaped_storage_middle
@escaped_storage_middle = alias i32 (i32), ptr @escaped_storage_impl
@escaped_argument_alias = alias i32 (i32), ptr @escaped_argument_impl
@escaped_integer_alias = alias i32 (i32), ptr @escaped_integer_impl
@stored = global ptr @escaped_storage_alias
@observed = global ptr null

define internal i32 @alias_target_impl(i32 %value) {
entry:
  %product = mul i32 %value, 7
  %result = add i32 %product, 3
  ret i32 %result
}

define internal i32 @alias_override_impl(i32 %value) {
entry:
  %result = xor i32 %value, 85
  ret i32 %result
}

define internal i32 @escaped_storage_impl(i32 %value) {
entry:
  %result = add i32 %value, 19
  ret i32 %result
}

define internal i32 @escaped_argument_impl(i32 %value) {
entry:
  %result = mul i32 %value, 3
  ret i32 %result
}

define internal i32 @escaped_integer_impl(i32 %value) {
entry:
  %result = sub i32 %value, 6
  ret i32 %result
}

define void @observe(ptr %function) noinline {
entry:
  store ptr %function, ptr @observed
  ret void
}

define i32 @main() {
entry:
  %target = call i32 @alias_chain(i32 5)
  %override = call i32 @alias_direct(i32 11)
  %storage_pointer = load ptr, ptr @stored
  %storage = call i32 %storage_pointer(i32 9)
  call void @observe(ptr @escaped_argument_alias)
  %argument_pointer = load ptr, ptr @observed
  %argument = call i32 %argument_pointer(i32 4)
  %address = ptrtoint ptr @escaped_integer_alias to i64
  %address_ok = icmp ne i64 %address, 0
  %integer = call i32 @escaped_integer_alias(i32 17)
  %sum0 = add i32 %target, %override
  %sum1 = add i32 %sum0, %storage
  %sum2 = add i32 %sum1, %argument
  %sum3 = add i32 %sum2, %integer
  %values_ok = icmp eq i32 %sum3, 183
  %ok = and i1 %address_ok, %values_ok
  %result = select i1 %ok, i32 0, i32 1
  ret i32 %result
}
