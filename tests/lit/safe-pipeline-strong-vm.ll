; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/safe-pipeline-strong-vm.yaml -passes=obf-safe-pipeline -S %s -o %t
; RUN: %lli %t

define i32 @strong_vm_fold(i32 %value) {
entry:
  %xor = xor i32 %value, 4660
  %add = add nsw i32 %xor, 85
  ret i32 %add
}

define i32 @main() {
entry:
  %folded = call i32 @strong_vm_fold(i32 0)
  %ok = icmp eq i32 %folded, 4745
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_entropy_anchor = external externally_initialized global i64, align 8
; CHECK-DAG: @__obf_vm_bc_strong_vm_fold = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @__obf_vm_retkey_strong_vm_fold = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_entropy_anchor_ref = external externally_initialized global ptr, align 8
; CHECK-DAG: @__obf_vm_target_strong_vm_fold = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-NOT: @llvm.global_ctors
; CHECK-LABEL: define i32 @strong_vm_fold(i32 %value)
; CHECK: %obf.entropy.direct = load i64, ptr @__obf_entropy_anchor
; CHECK: %obf.entropy.ref = load ptr, ptr @__obf_entropy_anchor_ref
; CHECK: %strong_vm_fold.obf.wrapper.token = xor i64
; CHECK: call i32 @__obf_vm_impl_strong_vm_fold(i32 %value, i64 %strong_vm_fold.obf.wrapper.token)
; CHECK-LABEL: define i32 @main()
; CHECK: %strong_vm_fold.obf.call.token = xor i64
; CHECK: %strong_vm_fold.obf.check = load i{{[0-9]+}}, ptr @__obf_vm_target_strong_vm_fold
; CHECK: br i1 %strong_vm_fold.obf.unresolved, label %strong_vm_fold.obf.resolve, label %strong_vm_fold.obf.call
; CHECK: strong_vm_fold.obf.resolve:
; CHECK-NOT: llvm.returnaddress
; CHECK: store i{{[0-9]+}} %strong_vm_fold.obf.resolved, ptr @__obf_vm_target_strong_vm_fold
; CHECK: strong_vm_fold.obf.call:
; CHECK: %strong_vm_fold.obf.key = load i{{[0-9]+}}, ptr @__obf_vm_key_strong_vm_fold
; CHECK: %strong_vm_fold.obf.indirect = inttoptr i{{[0-9]+}} %strong_vm_fold.obf.decoded to ptr
; CHECK: call i32 %strong_vm_fold.obf.indirect(i32 0, i64 %strong_vm_fold.obf.call.token)
; CHECK: %strong_vm_fold.obf.retkey = load i64, ptr @__obf_vm_retkey_strong_vm_fold
; CHECK: %strong_vm_fold.obf.retkey.trunc = trunc i64 %strong_vm_fold.obf.retkey to i32
; CHECK: %strong_vm_fold.obf.retdec = {{(or|sub) i32}}
; CHECK-NOT: define private void @__obf_vm_init_strong_vm_fold
; CHECK-LABEL: define i32 @__obf_vm_impl_strong_vm_fold(i32 %value, i64 %obf.hidden_token)
; CHECK: entry.obf.vm:
; CHECK-NOT: %obf.vm.pc = alloca i32
; CHECK-NOT: obf.flat.setup
; CHECK: %obf.vm.state = alloca i64
; CHECK: %obf.vm.token.state.match = icmp eq i64 %obf.hidden_token,
; CHECK: %obf.vm.dispatch.table = alloca [{{[0-9]+}} x i64]
; CHECK: load i8, ptr @__obf_vm_bc_strong_vm_fold
; CHECK: %obf.mba.xor.left{{.*}} = add i64
; CHECK: indirectbr ptr %obf.vm.dispatch.target
