; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

@.secret = private unnamed_addr constant [7 x i8] c"secret\00"

define i32 @first_char(ptr %p) {
entry:
  %first = load i8, ptr %p
  %is_s = icmp eq i8 %first, 115
  %code = select i1 %is_s, i32 0, i32 1
  ret i32 %code
}

define i32 @value() {
entry:
  ret i32 42
}

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @first_char(ptr @.secret)
  %value = call i32 @value()
  %folded = call i32 @fold_value(i32 %value)
  %ok1 = icmp eq i32 %result, 0
  %ok2 = icmp eq i32 %folded, 4723
  %ok = and i1 %ok1, %ok2
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK: @.secret = private unnamed_addr global [7 x i8]
; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_vm_bc_fold_value = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @__obf_vm_retkey_fold_value = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK: @__obf_vm_target_fold_value = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-NOT: @llvm.global_ctors
; CHECK: @__obf_{{cached|decoded}}__secret = internal global
; CHECK-LABEL: define i32 @value()
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: store i64 %obf.entropy.direct, ptr %obf.entropy.ref
; CHECK: %obf.entropy.indirect = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.const.mask = {{(sub|or) i32}}
; CHECK: %obf.const = {{(sub|or) i32}}
; CHECK: ret i32 %obf.const
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: %fold_value.obf.wrapper.token = xor i64
; CHECK: call i32 @__obf_vm_impl_fold_value(i32 %value, i64 %fold_value.obf.wrapper.token)
; CHECK-LABEL: define i32 @main()
; CHECK: call ptr @__obf_family_
; CHECK: %fold_value.obf.call.token = xor i64
; CHECK: %fold_value.obf.check = load i{{[0-9]+}}, ptr @__obf_vm_target_fold_value
; CHECK: %fold_value.obf.unresolved = icmp eq
; CHECK: fold_value.obf.resolve:
; CHECK-NOT: llvm.returnaddress
; CHECK: store i{{[0-9]+}} %fold_value.obf.resolved, ptr @__obf_vm_target_fold_value
; CHECK: fold_value.obf.call:
; CHECK: %fold_value.obf.key = load i{{[0-9]+}}, ptr @__obf_vm_key_fold_value
; CHECK: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; CHECK: call i32 %fold_value.obf.indirect(i32 %value, i64 %fold_value.obf.call.token)
; CHECK: %fold_value.obf.retkey = load i64, ptr @__obf_vm_retkey_fold_value
; CHECK: %fold_value.obf.retkey.trunc = trunc i64 %fold_value.obf.retkey to i32
; CHECK: %fold_value.obf.retdec = {{(or|sub) i32}}
; CHECK-NOT: define private void @__obf_vm_init_fold_value
; CHECK-LABEL: define i32 @__obf_vm_impl_fold_value(i32 %value, i64 %obf.hidden_token)
; CHECK: entry.obf.vm:
; CHECK: %obf.vm.token.state.match = icmp eq i64 %obf.hidden_token,
; CHECK: load i8, ptr @__obf_vm_bc_fold_value
; CHECK: indirectbr ptr %obf.vm.dispatch.target
; CHECK: define internal ptr @__obf_family_
