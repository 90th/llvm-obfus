; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-generated-names.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=VM --implicit-check-not='__obf_vm_impl_verify_license' --implicit-check-not='__obf_vm_impl_parse_secret_token' --implicit-check-not='__obf_vm_targetseed_verify_license' --implicit-check-not='__obf_vm_key_verify_license' --implicit-check-not='__obf_vm_retkey_verify_license' --implicit-check-not='__obf_vm_seedcase_parse_secret_token' --implicit-check-not='__obf_vm_target_parse_secret_token'
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-generated-names.yaml -passes=obf-vm -S %s -o %t.vm
; RUN: %lli %t.vm
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-generated-names.yaml -passes=obf-safe-pipeline -S %s -o %t.safe
; RUN: %lli %t.safe
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/opaque-generated-names-debug.yaml -passes=obf-vm -S %s -o - | %FileCheck %s --check-prefix=DEBUG

@.banner = private unnamed_addr constant [8 x i8] c"license\00"

define i32 @verify_license(i32 %x) {
entry:
  %masked = xor i32 %x, 42
  %score = add i32 %masked, 7
  ret i32 %score
}

define i32 @parse_secret_token(i32 %x) {
entry:
  %scaled = mul i32 %x, 3
  %score = add i32 %scaled, 11
  ret i32 %score
}

define i32 @main() {
entry:
  %license = call i32 @verify_license(i32 10)
  %token = call i32 @parse_secret_token(i32 5)
  %first = load i8, ptr @.banner, align 1
  %license.ok = icmp eq i32 %license, 39
  %token.ok = icmp eq i32 %token, 26
  %banner.ok = icmp eq i8 %first, 108
  %both = and i1 %license.ok, %token.ok
  %all = and i1 %both, %banner.ok
  %ret = select i1 %all, i32 0, i32 1
  ret i32 %ret
}

; VM-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}} = private unnamed_addr constant
; VM-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64
; VM-DAG: @__obf_vm_k_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}}
; VM-DAG: @__obf_vm_s_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}} 0
; VM-DAG: @__obf_vm_t_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}}
; VM-LABEL: define i32 @verify_license(i32 %x)
; VM-NOT: verify_license.obf.wrapper.check
; VM-NOT: @__obf_vm_seed_resolve
; VM: ptrtoint (ptr @[[VERIFY_THUNK:__obf_vm_e_[A-Za-z0-9_]+]] to i{{[0-9]+}})
; VM: call i32 %verify_license.obf.wrapper.indirect(i32 %x, i64 %verify_license.obf.wrapper.token)
; VM-LABEL: define i32 @parse_secret_token(i32 %x)
; VM: %parse_secret_token.obf.wrapper.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; VM: %parse_secret_token.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve
; VM: call i32 %parse_secret_token.obf.wrapper.indirect(i32 %x, i64 %parse_secret_token.obf.wrapper.token)
; VM-DAG: define internal i32 @[[VERIFY_THUNK]](i32 {{.*}}, i64 %obf.hidden_token)
; VM-DAG: define internal i32 @{{__obf_vm_i_[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; VM-DAG: define private i{{[0-9]+}} @__obf_vm_c_{{[A-Za-z0-9_]+}}

; DEBUG: @__obf_vm_retkey_verify_license = private global i64
; DEBUG: @__obf_vm_targetseed_verify_license = private global i{{[0-9]+}} 0
; DEBUG: @__obf_vm_key_verify_license = private global i{{[0-9]+}}
; DEBUG: @__obf_vm_target_parse_secret_token = private global i{{[0-9]+}}
; DEBUG: define internal i32 @__obf_vm_impl_verify_license(i32 %x, i64 %obf.hidden_token)
; DEBUG: define private i{{[0-9]+}} @__obf_vm_seedcase_parse_secret_token
