; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-token-binding.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-token-binding.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

; CHECK-DAG: @[[NORMAL_TARGET:__obf_vm_t_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @[[NORMAL_KEY:__obf_vm_k_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @[[STRONG_KEY:__obf_vm_k_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}

; CHECK-LABEL: define i32 @token_bound_normal(i32 %x)
; CHECK: %token_bound_normal.obf.wrapper.token = {{(add|sub|xor)}} i64
; CHECK: %token_bound_normal.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @[[NORMAL_KEY]]
; CHECK: %token_bound_normal.obf.wrapper.target.token = {{(add|sub|xor)}} i{{[0-9]+}}
; CHECK: %token_bound_normal.obf.wrapper.target.token.delta = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.target.token,
; CHECK: %token_bound_normal.obf.wrapper.target.token.mask = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.target.token.delta,
; CHECK: %token_bound_normal.obf.wrapper.target.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.target.key, %token_bound_normal.obf.wrapper.target.token.mask
; CHECK: store i{{[0-9]+}} %token_bound_normal.obf.wrapper.resolved, ptr @[[NORMAL_TARGET]]
; CHECK: %token_bound_normal.obf.wrapper.key = load i{{[0-9]+}}, ptr @[[NORMAL_KEY]]
; CHECK: %token_bound_normal.obf.wrapper.decode.token = {{(add|sub|xor)}} i{{[0-9]+}}
; CHECK: %token_bound_normal.obf.wrapper.decode.token.delta = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.decode.token,
; CHECK: %token_bound_normal.obf.wrapper.decode.token.mask = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.decode.token.delta,
; CHECK: %token_bound_normal.obf.wrapper.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.wrapper.key, %token_bound_normal.obf.wrapper.decode.token.mask
; CHECK: %token_bound_normal.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %token_bound_normal.obf.wrapper.decoded to ptr

; CHECK-LABEL: define i32 @token_bound_strong(i32 %x)
; CHECK-NOT: token_bound_strong.obf.wrapper.check
; CHECK: %token_bound_strong.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @[[STRONG_KEY]]
; CHECK: %token_bound_strong.obf.wrapper.target.token = {{(add|sub|xor)}} i{{[0-9]+}}
; CHECK: %token_bound_strong.obf.wrapper.target.token.delta = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.target.token,
; CHECK: %token_bound_strong.obf.wrapper.target.token.mask = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.target.token.delta,
; CHECK: %token_bound_strong.obf.wrapper.target.key.bound = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.target.key, %token_bound_strong.obf.wrapper.target.token.mask
; CHECK: %token_bound_strong.obf.wrapper.key = load i{{[0-9]+}}, ptr @[[STRONG_KEY]]
; CHECK: %token_bound_strong.obf.wrapper.decode.token = {{(add|sub|xor)}} i{{[0-9]+}}
; CHECK: %token_bound_strong.obf.wrapper.decode.token.delta = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.decode.token,
; CHECK: %token_bound_strong.obf.wrapper.decode.token.mask = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.decode.token.delta,
; CHECK: %token_bound_strong.obf.wrapper.key.bound = xor i{{[0-9]+}} %token_bound_strong.obf.wrapper.key, %token_bound_strong.obf.wrapper.decode.token.mask
; CHECK: call i32 %token_bound_strong.obf.wrapper.indirect(i32 %x, i64 %token_bound_strong.obf.wrapper.token)

; CHECK-LABEL: define i32 @normal_site_a()
; CHECK: %token_bound_normal.obf.call.token = {{(add|sub|xor)}} i64
; CHECK: %token_bound_normal.obf.check = load i{{[0-9]+}}, ptr @[[NORMAL_TARGET]]
; CHECK: %token_bound_normal.obf.target.key = load i{{[0-9]+}}, ptr @[[NORMAL_KEY]]
; CHECK: %token_bound_normal.obf.target.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.target.key, %token_bound_normal.obf.target.token.mask
; CHECK: %token_bound_normal.obf.key = load i{{[0-9]+}}, ptr @[[NORMAL_KEY]]
; CHECK: %token_bound_normal.obf.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.key, %token_bound_normal.obf.decode.token.mask
; CHECK: call i32 %token_bound_normal.obf.indirect(i32 9, i64 %token_bound_normal.obf.call.token)

; CHECK-LABEL: define i32 @main()
; CHECK: %token_bound_normal.obf.call.token = {{(add|sub|xor)}} i64
; CHECK: %token_bound_normal.obf.check = load i{{[0-9]+}}, ptr @[[NORMAL_TARGET]]
; CHECK: %token_bound_normal.obf.target.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.target.key, %token_bound_normal.obf.target.token.mask
; CHECK: %token_bound_normal.obf.key.bound = xor i{{[0-9]+}} %token_bound_normal.obf.key, %token_bound_normal.obf.decode.token.mask
; CHECK: call i32 %token_bound_normal.obf.indirect(i32 7, i64 %token_bound_normal.obf.call.token)
; CHECK: %token_bound_strong.obf.call.token = {{(add|sub|xor)}} i64
; CHECK: %token_bound_strong.obf.target.key.bound = xor i{{[0-9]+}} %token_bound_strong.obf.target.key, %token_bound_strong.obf.target.token.mask
; CHECK: %token_bound_strong.obf.key.bound = xor i{{[0-9]+}} %token_bound_strong.obf.key, %token_bound_strong.obf.decode.token.mask
; CHECK: call i32 %token_bound_strong.obf.indirect(i32 12, i64 %token_bound_strong.obf.call.token)
; CHECK: %via.caller = call i32 @normal_site_a()

define i32 @token_bound_normal(i32 %x) {
entry:
  %mul = mul i32 %x, 3
  %sum = add i32 %mul, 4
  ret i32 %sum
}

define i32 @token_bound_strong(i32 %x) {
entry:
  %xor = xor i32 %x, 19
  %sum = add i32 %xor, 8
  ret i32 %sum
}

define i32 @normal_site_a() {
entry:
  %normal = call i32 @token_bound_normal(i32 9)
  ret i32 %normal
}

define i32 @main() {
entry:
  %normal = call i32 @token_bound_normal(i32 7)
  %strong = call i32 @token_bound_strong(i32 12)
  %via.caller = call i32 @normal_site_a()
  %normal.ok = icmp eq i32 %normal, 25
  %strong.ok = icmp eq i32 %strong, 39
  %caller.ok = icmp eq i32 %via.caller, 31
  %normal.and = and i1 %normal.ok, %strong.ok
  %ok = and i1 %normal.and, %caller.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
