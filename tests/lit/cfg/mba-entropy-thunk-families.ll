; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=IR
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes=obf-constant-encode -S %s -o - | %FileCheck %s --check-prefix=SHAPES
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes=obf-constant-encode -S %s -o - | %opt -passes=verify -disable-output
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %lli %t

define i32 @entropy_thunk_a(i32 %x) {
entry:
  %a = add i32 %x, 17
  %b = xor i32 %a, 85
  %c = sub i32 %b, 123
  ret i32 %c
}

define i32 @entropy_thunk_b(i32 %x) {
entry:
  %a = xor i32 %x, 4660
  %b = add i32 %a, 85
  %c = sub i32 %b, 19
  ret i32 %c
}

define i32 @entropy_thunk_c(i32 %x) {
entry:
  %a = add i32 %x, 9
  %b = mul i32 %a, 5
  %c = xor i32 %b, 99
  ret i32 %c
}

define i32 @entropy_thunk_d(i32 %x) {
entry:
  %a = sub i32 %x, 41
  %b = xor i32 %a, 7
  %c = add i32 %b, 3
  ret i32 %c
}

define i32 @main() {
entry:
  %a = call i32 @entropy_thunk_a(i32 7)
  %b = call i32 @entropy_thunk_b(i32 10)
  %c = call i32 @entropy_thunk_c(i32 3)
  %d = call i32 @entropy_thunk_d(i32 50)
  %ab = add i32 %a, %b
  %cd = add i32 %c, %d
  %sum = add i32 %ab, %cd
  %ok = icmp eq i32 %sum, 4802
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; IR-LABEL: define i32 @entropy_thunk_a(i32 %x)
; IR: %obf.entropy.cache = alloca { i64, i64 }, align 8
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: = call i64 @__obf_entropy_thunk_
; IR-NOT: call { i64, i64 } @rt_core_ep0()
; IR: ret i32
; IR-LABEL: define i32 @entropy_thunk_b(i32 %x)
; IR: %obf.entropy.cache = alloca { i64, i64 }, align 8
; IR: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR-NOT: = call i64 @__obf_entropy_thunk_
; IR-NOT: call { i64, i64 } @rt_core_ep0()
; IR: ret i32
; IR-LABEL: define internal {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; IR: call { i64, i64 } @rt_core_ep{{[0-4]}}()

; SHAPES-DAG: entropy.thunk.swap
; SHAPES-DAG: entropy.thunk.select
