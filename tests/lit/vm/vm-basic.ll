; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-basic.yaml -passes=obf-vm -S %s -o - | %opt -passes='instcombine<no-verify-fixpoint>' -S -o - | %FileCheck %s --check-prefix=INST
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-basic.yaml -passes=obf-vm -S %s -o %t
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

; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-DAG: @[[VMBC:__obf_vm_bc_i_[A-Za-z0-9_]+]] = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @[[RETKEY:__obf_vm_retkey_i_[A-Za-z0-9_]+]] = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @[[TARGET:__obf_vm_t_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @[[TARGETSEED:__obf_vm_s_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} 0
; CHECK-DAG: @[[KEY:__obf_vm_k_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}
; CHECK-DAG: @llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]
; CHECK-LABEL: define i32 @fold_value(i32 %value)
; CHECK: call {{(void|\{ i64, i64 \})}} @__obf_entropy_thunk_
; CHECK: %obf.entropy.pair = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.entropy.direct = extractvalue { i64, i64 } %obf.entropy.pair, 0
; CHECK: %fold_value.obf.wrapper.token = {{(add|sub|xor) i64}}
; CHECK: %fold_value.obf.wrapper.check = load i{{[0-9]+}}, ptr @[[TARGET]]
; CHECK: br i1 %fold_value.obf.wrapper.unresolved, label %fold_value.obf.wrapper.resolve, label %fold_value.obf.wrapper.call
; CHECK: fold_value.obf.wrapper.resolve:
; CHECK: %fold_value.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @[[KEY]]
; CHECK: %fold_value.obf.wrapper.target.seed.base = load i{{[0-9]+}}, ptr @[[TARGETSEED]]
; CHECK: %fold_value.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %fold_value.obf.wrapper.target.key, i{{[0-9]+}} %fold_value.obf.wrapper.target.base)
; CHECK: %fold_value.obf.wrapper.real.int = sub i{{[0-9]+}} %fold_value.obf.wrapper.target.value, %fold_value.obf.wrapper.target.base
; CHECK: store i{{[0-9]+}} %fold_value.obf.wrapper.resolved, ptr @[[TARGET]]
; CHECK: fold_value.obf.wrapper.call:
; CHECK: %fold_value.obf.wrapper.key = load i{{[0-9]+}}, ptr @[[KEY]]
; CHECK: %fold_value.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.wrapper.decoded to ptr
; CHECK: %fold_value.obf.wrapper.call{{[0-9]*}} = call i32 %fold_value.obf.wrapper.indirect(i32 %value, i64 %fold_value.obf.wrapper.token)
; CHECK: %fold_value.obf.retkey = load i64, ptr @[[RETKEY]]
; CHECK: %fold_value.obf.retkey.cast = trunc i64 %fold_value.obf.retkey.bound to i32
; CHECK: %fold_value.obf.retdec = {{(add|sub) i32}}
; CHECK-LABEL: define i32 @main()
; CHECK: %fold_value.obf.call.token = {{(add|sub|xor) i64}}
; CHECK: %fold_value.obf.check = load i{{[0-9]+}}, ptr @[[TARGET]]
; CHECK: %fold_value.obf.unresolved = icmp eq i{{[0-9]+}} %fold_value.obf.check,
; CHECK: br i1 %fold_value.obf.unresolved, label %fold_value.obf.resolve, label %fold_value.obf.call
; CHECK: fold_value.obf.resolve:
; CHECK-NOT: llvm.returnaddress
; CHECK: store i{{[0-9]+}} %fold_value.obf.resolved, ptr @[[TARGET]]
; CHECK: fold_value.obf.call:
; CHECK: %fold_value.obf.encoded = phi i{{[0-9]+}}
; CHECK: %fold_value.obf.key = load i{{[0-9]+}}, ptr @[[KEY]]
; CHECK: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; CHECK: call i32 %fold_value.obf.indirect(i32 0, i64 %fold_value.obf.call.token)
; CHECK: %fold_value.obf.retkey = load i64, ptr @[[RETKEY]]
; CHECK: %fold_value.obf.retkey.bound = {{(add|sub) i64}}
; CHECK: %fold_value.obf.retkey.cast = trunc i64 %fold_value.obf.retkey.bound to i32
; CHECK: %fold_value.obf.retdec = {{(add|sub) i32}}
; CHECK: icmp eq i32 %fold_value.obf.retdec,
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %value, i64 %obf.hidden_token)
; CHECK-DAG: entry.obf.vm:
; CHECK-DAG: %obf.vm.state = alloca {
; CHECK-DAG: %obf.vm.pred.slot = alloca i32
; CHECK-DAG: %obf.vm.token.state.match = icmp eq i64 %obf.hidden_token,
; CHECK-DAG: %obf.vm.dispatch.table = alloca [{{[0-9]+}} x i64]
; CHECK-DAG: %obf.vm.dispatch.key.mix
; CHECK-DAG: %obf.vm.dispatch.key.affine.mul
; CHECK-DAG: %obf.vm.dispatch.key =
; CHECK-DAG: {{^vm\.[0-9]+:}}
; CHECK-DAG: %obf.vm.ptr.const = load ptr, ptr @__obf_vm_ptrconst_
; CHECK-DAG: %obf.vm.integrity.byte.ptr = getelementptr inbounds
; CHECK-DAG: %obf.vm.integrity.byte.window = load i32, ptr %obf.vm.integrity.byte.ptr, align 1
; CHECK-DAG: %obf.vm.integrity.byte = trunc i32 %obf.vm.integrity.byte.shr to i8
; CHECK-DAG: %obf.vm.integrity.state = load i64, ptr %obf.vm.state.bc
; CHECK-DAG: {{%obf\.vm\.opcode\.wide[^ ]* = }}zext i8
; CHECK-DAG: store i32 {{%obf\.vm\.opcode\.split\.(low|high)\.delta[^,]*}}, ptr %obf.vm.pred.slot
; CHECK-DAG: br label %obf.vm.opcode.pred.merge
; CHECK-DAG: {{^obf\.vm\.opcode\.pred\.merge[0-9]*:}}
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.(low|high)\.reload[^ ]* = }}load i32, ptr %obf.vm.pred.slot
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.low\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.high\.ok[^ ]* = }}icmp eq i32 {{[^,]+}}, 0
; CHECK-DAG: {{%obf\.vm\.opcode\.split\.match[^ ]* = }}and i1
; CHECK-DAG: br i1 {{[^,]+}}, label %obf.vm.route.entry.{{[0-9]+}}, label %obf.vm.fail.shared
; CHECK-DAG: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; CHECK-DAG: br label %vm.exec.{{[0-9]+}}
; CHECK-DAG: indirectbr ptr
; CHECK-DAG: {{^vm\.exec\.[0-9]+:}}
; CHECK-DAG: %obf.vm.ret.state = load i64, ptr %obf.vm.state.bc
; CHECK-DAG: %obf.vm.ret.retkey = load i64, ptr @[[RETKEY]]
; CHECK-DAG: ret i32 %obf.vm.ret.encoded
; CHECK-LABEL: define private i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %obf.target.key, i{{[0-9]+}} %obf.share.base)
; CHECK-LABEL: define private void @__obf_vm_seed_ctor()

; INST-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; INST-LABEL: define i32 @fold_value(i32 %value)
; INST: %fold_value.obf.wrapper.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; INST: %fold_value.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; INST: %fold_value.obf.wrapper.target.seed.base = load i{{[0-9]+}}, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; INST: %fold_value.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %fold_value.obf.wrapper.target.key, i{{[0-9]+}} %fold_value.obf.wrapper.target.base)
; INST: %obf.mba.xor.affine.or
; INST: %fold_value.obf.wrapper.real.int = {{(add|sub) i[0-9]+}}
; INST: %fold_value.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %obf.mba.xor.affine.{{.*}}.dec{{[0-9]*}} to ptr
; INST: call i32 %fold_value.obf.wrapper.indirect(i32 %value, i64 {{(%fold_value\.obf\.wrapper\.token|-?[0-9]+)}})
; INST-LABEL: define i32 @main()
; INST: %fold_value.obf.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; INST: br i1
; INST: %fold_value.obf.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; INST: %fold_value.obf.indirect = inttoptr i{{[0-9]+}} %fold_value.obf.decoded to ptr
; INST: call i32 %fold_value.obf.indirect(i32 0, i64 {{(%fold_value\.obf\.call\.token|-?[0-9]+)}})
; INST: %fold_value.obf.retkey = load i64, ptr @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}}
; INST: {{(%fold_value\.obf\.retkey\.bound = (add|sub|xor) i64|%[0-9]+ = trunc i64 %fold_value\.obf\.retkey to i32|%obf\.mba\.xor\.affine\.)}}
; INST: {{(%fold_value\.obf\.retdec = (add|sub|xor) i32|%[0-9]+ = xor i32 %fold_value\.obf\.callsite, %[0-9]+)}}
; INST-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %value, i64 %obf.hidden_token)
; INST: %obf.vm.state = alloca {
; INST: %obf.entropy.cache = alloca { i64, i64 }
; INST: {{^vm\.[0-9]+:}}
; INST-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i8
; INST-NOT: {{%obf\.vm\.opcode\.match[^ ]* = }}icmp eq i32
; INST: indirectbr ptr
; INST: {{^obf\.vm\.route\.entry\.[0-9]+:}}
; INST: br label %vm.exec.{{[0-9]+}}
; INST: {{^vm\.exec\.[0-9]+:}}
; INST-LABEL: define internal i32 @__obf_vm_e_{{[A-Za-z0-9_]+}}(i32 %value, i64 %obf.hidden_token)
; INST: obf.vm.entry.thunk:
; INST: call i32 {{.*}}@__obf_vm_i_{{[A-Za-z0-9_]+}}{{.*}}(i32 %value, i64 %obf.hidden_token)
