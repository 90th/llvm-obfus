; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %opt -passes=instcombine -S -o - | %FileCheck %s --check-prefix=INST
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

; CHECK: @__obf_vm_bc_fold_value = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK: @__obf_vm_target_fold_value = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-NOT: @llvm.global_ctors
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: entry.obf.vm:
; CHECK-NOT: %obf.vm.pc = alloca i32
; CHECK-NOT: dispatch.obf.vm:
; CHECK: %obf.vm.state = alloca i64
; CHECK: %obf.vm.dispatch.table = alloca [{{[0-9]+}} x i64]
 ; CHECK: load volatile i64, ptr %obf.vm.seed
; CHECK: load i8, ptr @__obf_vm_bc_fold_value
; CHECK: load volatile i64, ptr %obf.vm.state
; CHECK: %obf.vm.integrity.byte = load i8, ptr getelementptr inbounds
; CHECK: %obf.vm.integrity.state = load volatile i64, ptr %obf.vm.state
; CHECK: %obf.vm.integrity.fold = xor i64
; CHECK: %obf.vm.dispatch.encoded = load volatile i64, ptr %obf.vm.dispatch.slot
; CHECK: indirectbr ptr %obf.vm.dispatch.target
; CHECK-LABEL: define i32 @main()
; CHECK: %fold_value.obf.check = load volatile i{{[0-9]+}}, ptr @__obf_vm_target_fold_value
; CHECK: %fold_value.obf.unresolved = icmp eq i{{[0-9]+}} %fold_value.obf.check,
; CHECK: br i1 %fold_value.obf.unresolved, label %fold_value.obf.resolve, label %fold_value.obf.call
; CHECK: fold_value.obf.resolve:
; CHECK: %fold_value.obf.retaddr = call ptr @llvm.returnaddress(i32 0)
; CHECK: store volatile i{{[0-9]+}} %fold_value.obf.resolved, ptr @__obf_vm_target_fold_value
; CHECK: fold_value.obf.call:
; CHECK: %fold_value.obf.encoded = phi i{{[0-9]+}}
; CHECK: %fold_value.obf.key = load volatile i{{[0-9]+}}, ptr @__obf_vm_key_fold_value
; CHECK: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; CHECK: call i32 %fold_value.obf.indirect(i32 0)
; CHECK-NOT: define private void @__obf_vm_init_fold_value

; INST-LABEL: define i32 @fold_value(i32 %value)
; INST-NOT: %obf.vm.pc = alloca i32
; INST-NOT: switch i32
; INST: %obf.vm.state = alloca i64
; INST: load volatile i64, ptr %obf.vm.seed
; INST: load volatile i64, ptr %obf.vm.state
; INST: indirectbr ptr %obf.vm.dispatch.target
; INST-LABEL: define i32 @main()
; INST: %fold_value.obf.check = load volatile i{{[0-9]+}}, ptr @__obf_vm_target_fold_value
; INST: br i1
; INST: %fold_value.obf.key = load volatile i{{[0-9]+}}, ptr @__obf_vm_key_fold_value
; INST: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
