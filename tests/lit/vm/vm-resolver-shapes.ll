; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-resolver-shapes.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --implicit-check-not='@__obf_vm_target_strong_vm_value'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-resolver-shapes.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t
; RUN: %FileCheck %s --check-prefix=TOKENBIND --input-file=%t

define i32 @normal_vm_value(i32 %x) {
entry:
  %mul = mul i32 %x, 2
  %sum = add i32 %mul, 7
  ret i32 %sum
}

define i32 @strong_vm_value(i32 %x) {
entry:
  %xor = xor i32 %x, 85
  %sum = add i32 %xor, 3
  ret i32 %sum
}

define i32 @main() {
entry:
  %normal = call i32 @normal_vm_value(i32 10)
  %strong = call i32 @strong_vm_value(i32 12)
  %normal.ok = icmp eq i32 %normal, 27
  %strong.ok = icmp eq i32 %strong, 92
  %ok = and i1 %normal.ok, %strong.ok
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @[[NORMAL_TARGET:__obf_vm_t_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @[[NORMAL_SEED:__obf_vm_s_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} 0
; CHECK-DAG: @[[STRONG_SEED:__obf_vm_s_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} 0

; CHECK-LABEL: define i32 @normal_vm_value(i32 %x)
; CHECK: %normal_vm_value.obf.wrapper.check = load i{{[0-9]+}}, ptr @[[NORMAL_TARGET]]
; CHECK: %normal_vm_value.obf.wrapper.unresolved = icmp eq
; CHECK: store i{{[0-9]+}} %normal_vm_value.obf.wrapper.resolved, ptr @[[NORMAL_TARGET]]
; CHECK: %normal_vm_value.obf.wrapper.encoded = phi i{{[0-9]+}}
; CHECK: call i32 %normal_vm_value.obf.wrapper.indirect(i32 %x, i64 %normal_vm_value.obf.wrapper.token)

; CHECK-LABEL: define i32 @strong_vm_value(i32 %x)
; CHECK-NOT: strong_vm_value.obf.wrapper.check
; CHECK-NOT: strong_vm_value.obf.wrapper.unresolved
; CHECK-NOT: strong_vm_value.obf.wrapper.encoded
; CHECK: %strong_vm_value.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @[[STRONG_KEY:__obf_vm_k_[A-Za-z0-9_]+]]
; CHECK: ptrtoint (ptr @[[STRONG_THUNK:__obf_vm_e_[A-Za-z0-9_]+]] to i{{[0-9]+}})
; CHECK-NOT: {{.*}}.ptrmat.direct
; CHECK: {{.*}}.ptrmat.{{split|addsub}}
; CHECK: call i32 %strong_vm_value.obf.wrapper.indirect(i32 %x, i64 %strong_vm_value.obf.wrapper.token)

; CHECK-LABEL: define i32 @main()
; CHECK: %normal_vm_value.obf.check = load i{{[0-9]+}}, ptr @[[NORMAL_TARGET]]
; CHECK: %normal_vm_value.obf.encoded = phi i{{[0-9]+}}
; CHECK: call i32 %normal_vm_value.obf.indirect(i32 10, i64 %normal_vm_value.obf.call.token)
; CHECK-NOT: strong_vm_value.obf.check
; CHECK-NOT: strong_vm_value.obf.unresolved
; CHECK-NOT: strong_vm_value.obf.encoded
; CHECK: %strong_vm_value.obf.target.key = load i{{[0-9]+}}, ptr @[[STRONG_KEY]]
; CHECK: ptrtoint (ptr @[[STRONG_THUNK]] to i{{[0-9]+}})
; CHECK-NOT: {{.*}}.ptrmat.direct
; CHECK: {{.*}}.ptrmat.{{split|addsub}}
; CHECK: call i32 %strong_vm_value.obf.indirect(i32 12, i64 %strong_vm_value.obf.call.token)

; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: indirectbr ptr
; CHECK: define internal i32 @[[STRONG_THUNK]](i32 {{.*}}, i64 %obf.hidden_token)
; CHECK-NOT: indirectbr ptr

; Rank 2 regression guard: the VM target/decode key must be XOR-bound by a
; token-derived mask on both the encode and decode paths and then feed the
; resolve combine, so the pre-fix static-XOR cancellation (mixed/unmixed, see
; commit 30d6bc1) cannot silently return. target.token/decode.token are the
; entangled VM hidden token (built by build_vm_target_token_mask); this pins the
; token -> mask -> key.bound binding wiring. The entangle family varies per run,
; so the token is matched only as an obf.entangle.* output, not by family.
; TOKENBIND-LABEL: define i32 @strong_vm_value(i32 %x)
; encode: entangled token -> delta -> mask -> target.key.bound -> resolve combine
; TOKENBIND: %strong_vm_value.obf.wrapper.target.token = {{.*}}%obf.entangle.
; TOKENBIND: %strong_vm_value.obf.wrapper.target.token.delta = xor i64 %strong_vm_value.obf.wrapper.target.token,
; TOKENBIND: %strong_vm_value.obf.wrapper.target.token.mask = xor i64 %strong_vm_value.obf.wrapper.target.token.delta,
; TOKENBIND: %strong_vm_value.obf.wrapper.target.key.bound = xor i64 %strong_vm_value.obf.wrapper.target.key, %strong_vm_value.obf.wrapper.target.token.mask
; TOKENBIND: i64 {{.*}}%strong_vm_value.obf.wrapper.target.key.bound
; decode: entangled token -> delta -> mask -> key.bound -> resolve combine
; TOKENBIND: %strong_vm_value.obf.wrapper.decode.token = {{.*}}%obf.entangle.
; TOKENBIND: %strong_vm_value.obf.wrapper.decode.token.delta = xor i64 %strong_vm_value.obf.wrapper.decode.token,
; TOKENBIND: %strong_vm_value.obf.wrapper.decode.token.mask = xor i64 %strong_vm_value.obf.wrapper.decode.token.delta,
; TOKENBIND: %strong_vm_value.obf.wrapper.key.bound = xor i64 %strong_vm_value.obf.wrapper.key, %strong_vm_value.obf.wrapper.decode.token.mask
; TOKENBIND: i64 {{.*}}%strong_vm_value.obf.wrapper.key.bound
