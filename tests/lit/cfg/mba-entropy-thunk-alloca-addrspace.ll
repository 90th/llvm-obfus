; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-thunk-families.yaml -passes=obf-constant-encode -S %s -o %t
; RUN: %FileCheck %s --check-prefix=IR < %t
; RUN: %opt -passes=verify -disable-output %t
; RUN: %lli %t

target datalayout = "e-p:64:64-p1:64:64-A1"

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

; IR-LABEL: define i32 @entropy_thunk_c(i32 %x)
; IR: %obf.entropy.cache = alloca { i64, i64 }, align 8, addrspace(1)
; IR-NEXT: %obf.entropy.cache.init = call { i64, i64 } [[THUNK_C:@__obf_entropy_thunk_[0-9a-fx]+]]()
; IR-NEXT: store { i64, i64 } %obf.entropy.cache.init, ptr addrspace(1) %obf.entropy.cache, align 8

; IR-LABEL: define i32 @main()
; IR: %obf.entropy.cache = alloca { i64, i64 }, align 8, addrspace(1)
; IR-NEXT: call void [[THUNK_MAIN:@__obf_entropy_thunk_[0-9a-fx]+]](ptr addrspace(1) %obf.entropy.cache)
; IR-NEXT: %obf.entropy.pair = load { i64, i64 }, ptr addrspace(1) %obf.entropy.cache, align 8

; IR: define internal { i64, i64 } [[THUNK_C]]()
; IR: call { i64, i64 } @rt_core_ep{{[0-4]}}()
; IR: ret { i64, i64 }

; IR: define internal void [[THUNK_MAIN]](ptr addrspace(1) %out_buf)
; IR: call { i64, i64 } @rt_core_ep{{[0-4]}}()
; IR: getelementptr inbounds{{.*}} { i64, i64 }, ptr addrspace(1) %out_buf, i32 0, i32 0
; IR: getelementptr inbounds{{.*}} { i64, i64 }, ptr addrspace(1) %out_buf, i32 0, i32 1
; IR: store i64 %{{.*}}, ptr addrspace(1) %{{.*}}
; IR: store i64 %{{.*}}, ptr addrspace(1) %{{.*}}
; IR: ret void
