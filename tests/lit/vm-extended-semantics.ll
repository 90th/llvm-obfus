; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-extended-semantics.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-extended-semantics.yaml -passes=obf-feature-report -disable-output %s | %FileCheck %s --check-prefix=REPORT
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-extended-semantics.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)
declare void @llvm.memmove.p0.p0.i64(ptr, ptr, i64, i1)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

@src.bytes = private unnamed_addr constant [4 x i8] c"ABCD"

define i32 @extended_semantics(i32 %x, float %f, ptr %dst) {
entry:
  %neg = fneg float %f
  %neg.i = fptosi float %neg to i32
  %vec0 = insertelement <2 x i32> poison, i32 %x, i32 0
  %vec1 = insertelement <2 x i32> %vec0, i32 %neg.i, i32 1
  %elt = extractelement <2 x i32> %vec1, i32 1
  %shuf = shufflevector <2 x i32> %vec1, <2 x i32> zeroinitializer, <2 x i32> <i32 1, i32 0>
  %elt2 = extractelement <2 x i32> %shuf, i32 1
  %agg0 = insertvalue { i32, i32 } poison, i32 %elt, 0
  %agg1 = insertvalue { i32, i32 } %agg0, i32 %elt2, 1
  %aggv = extractvalue { i32, i32 } %agg1, 1
  call void @llvm.memcpy.p0.p0.i64(ptr %dst, ptr @src.bytes, i64 4, i1 false)
  call void @llvm.memmove.p0.p0.i64(ptr %dst, ptr %dst, i64 4, i1 false)
  call void @llvm.memset.p0.i64(ptr %dst, i8 90, i64 1, i1 false)
  %sum = add i32 %aggv, %neg.i
  ret i32 %sum
}

define i32 @main() {
entry:
  %buf = alloca [4 x i8], align 1
  %ptr = getelementptr inbounds [4 x i8], ptr %buf, i32 0, i32 0
  %ret = call i32 @extended_semantics(i32 5, float 3.000000e+00, ptr %ptr)
  %c0 = load i8, ptr %ptr, align 1
  %ok0 = icmp eq i8 %c0, 90
  %ok1 = icmp eq i32 %ret, 2
  %ok = and i1 %ok0, %ok1
  %code = select i1 %ok, i32 0, i32 1
  ret i32 %code
}

; CHECK-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}} = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; CHECK-DAG: @__obf_vm_s_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}} 0
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-LABEL: define i32 @extended_semantics(i32 %x, float %f, ptr %dst)
; CHECK: %extended_semantics.obf.wrapper.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; CHECK: %extended_semantics.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %extended_semantics.obf.wrapper.target.seed.base = load i{{[0-9]+}}, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; CHECK: %extended_semantics.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %extended_semantics.obf.wrapper.target.key, i{{[0-9]+}} %extended_semantics.obf.wrapper.target.base)
; CHECK: %extended_semantics.obf.wrapper.real.int = sub i{{[0-9]+}} %extended_semantics.obf.wrapper.target.value, %extended_semantics.obf.wrapper.target.base
; CHECK: %extended_semantics.obf.wrapper.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %extended_semantics.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %extended_semantics.obf.wrapper.decoded to ptr
; CHECK: call i32 %extended_semantics.obf.wrapper.indirect(i32 %x, float %f, ptr %dst, i64 %extended_semantics.obf.wrapper.token)
; CHECK: %extended_semantics.obf.retkey = load i64, ptr @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}}
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, float %f, ptr %dst, i64 %obf.hidden_token)
; CHECK-DAG: %obf.vm.slot.6.0 = alloca <2 x i32>, align 8
; CHECK-DAG: %obf.vm.slot.9.0 = alloca <2 x i32>, align 8
; CHECK-DAG: %obf.vm.slot.11.0 = alloca { i32, i32 }, align 8
; CHECK-DAG: %obf.vm.slot.12.0 = alloca { i32, i32 }, align 8
; CHECK: %obf.vm.dispatch.table = alloca [15 x i64], align 8
; CHECK: %obf.vm.fneg = fneg float
; CHECK: insertelement <2 x i32> poison
; CHECK: insertelement <2 x i32> %{{[^,]+}}, i32 %{{[^,]+}}, i32 1
; CHECK: extractelement <2 x i32>
; CHECK: shufflevector <2 x i32>
; CHECK: insertvalue { i32, i32 } poison
; CHECK: insertvalue { i32, i32 } %{{[^,]+}}, i32 %{{[^,]+}}, 1
; CHECK: extractvalue { i32, i32 }
; CHECK: call void @llvm.memcpy.p0.p0.i64
; CHECK: call void @llvm.memmove.p0.p0.i64
; CHECK: call void @llvm.memset.p0.i64
; CHECK: indirectbr ptr

; REPORT-DAG: "name":"extended_semantics",
; REPORT-DAG: "has_vector_ops":true
; REPORT-DAG: "allow_vm":true
; REPORT-DAG: "detail":"config match:extended_semantics"
; REPORT-DAG: "pass":"vm","status":"applied","target_kind":"function","target_name":"extended_semantics"
