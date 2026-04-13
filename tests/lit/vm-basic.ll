; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %opt -passes='instcombine<no-verify-fixpoint>' -S -o - | %FileCheck %s --check-prefix=INST
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

define i32 @fold_value(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %result = call i32 @fold_value(i32 0)
  %ok = icmp eq i32 %result, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_vm_bc_fold_value = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @__obf_vm_retkey_fold_value = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK: @__obf_vm_target_fold_value = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-NOT: @llvm.global_ctors
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: %fold_value.obf.wrapper.token = xor i64
; CHECK: call i32 @__obf_vm_impl_fold_value(i32 %value, i64 %fold_value.obf.wrapper.token)
; CHECK-LABEL: define i32 @main()
; CHECK: %fold_value.obf.call.token = xor i64
; CHECK: %fold_value.obf.check = load i{{[0-9]+}}, ptr @__obf_vm_target_fold_value
; CHECK: %fold_value.obf.unresolved = icmp eq i{{[0-9]+}} %fold_value.obf.check,
; CHECK: br i1 %fold_value.obf.unresolved, label %fold_value.obf.resolve, label %fold_value.obf.call
; CHECK: fold_value.obf.resolve:
; CHECK-NOT: llvm.returnaddress
; CHECK: store i{{[0-9]+}} %fold_value.obf.resolved, ptr @__obf_vm_target_fold_value
; CHECK: fold_value.obf.call:
; CHECK: %fold_value.obf.encoded = phi i{{[0-9]+}}
; CHECK: %fold_value.obf.key = load i{{[0-9]+}}, ptr @__obf_vm_key_fold_value
; CHECK: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; CHECK: call i32 %fold_value.obf.indirect(i32 0, i64 %fold_value.obf.call.token)
; CHECK: %fold_value.obf.retkey = load i64, ptr @__obf_vm_retkey_fold_value
; CHECK: %fold_value.obf.retkey.trunc = trunc i64 %fold_value.obf.retkey to i32
; CHECK: %fold_value.obf.retdec = {{(or|sub) i32}}
; CHECK: icmp eq i32 %fold_value.obf.retdec,
; CHECK-NOT: define private void @__obf_vm_init_fold_value
; CHECK-LABEL: define i32 @__obf_vm_impl_fold_value(i32 %value, i64 %obf.hidden_token)
; CHECK: entry.obf.vm:
; CHECK-NOT: %obf.vm.pc = alloca i32
; CHECK-NOT: dispatch.obf.vm:
; CHECK: %obf.vm.state = alloca i64
; CHECK: %obf.vm.token.state.match = icmp eq i64 %obf.hidden_token,
; CHECK: %obf.vm.dispatch.table = alloca [{{[0-9]+}} x i64]
; CHECK: load i8, ptr @__obf_vm_bc_fold_value
; CHECK: %obf.vm.integrity.byte = load i8, ptr getelementptr inbounds
; CHECK: %obf.vm.integrity.state = load i64, ptr %obf.vm.state
; CHECK: %obf.vm.ret.state = load i64, ptr %obf.vm.state
; CHECK: %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_fold_value
; CHECK: ret i32 %obf.vm.ret.encoded
; CHECK: indirectbr ptr %obf.vm.dispatch.target

; INST-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; INST-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; INST-LABEL: define i32 @fold_value(i32 %value)
; INST: %fold_value.obf.wrapper.token = xor i64
; INST: call i32 @__obf_vm_impl_fold_value(i32 %value, i64 %fold_value.obf.wrapper.token)
; INST-LABEL: define i32 @main()
; INST: %fold_value.obf.check = load i{{[0-9]+}}, ptr @__obf_vm_target_fold_value
; INST: br i1
; INST: %fold_value.obf.key = load i{{[0-9]+}}, ptr @__obf_vm_key_fold_value
; INST: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; INST: call i32 %fold_value.obf.indirect(i32 0, i64 %fold_value.obf.call.token)
; INST: %fold_value.obf.retkey = load i64, ptr @__obf_vm_retkey_fold_value
; INST: %fold_value.obf.retdec = {{(or|sub) i32}}
; INST-LABEL: define i32 @__obf_vm_impl_fold_value(i32 %value, i64 %obf.hidden_token)
; INST: %obf.vm.state = alloca i64
; INST: %obf.vm.ret.retkey = load i64, ptr @__obf_vm_retkey_fold_value
; INST: indirectbr ptr %obf.vm.dispatch.target
