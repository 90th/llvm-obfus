; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-expanded.yaml -passes=obf-vm -S %s -o - | %FileCheck %s
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/Inputs/vm-expanded.yaml -passes=obf-vm -S %s -o %t
; RUN: %lli %t

@src.slot = global i32 37
@dst.slot = global i32 0
@arr.slot = global [4 x i32] [i32 9, i32 13, i32 21, i32 34]

define i32 @branch_phi(i32 %x) {
entry:
  %cond = icmp sgt i32 %x, 10
  br i1 %cond, label %big, label %small

big:
  %a = add nsw i32 %x, 7
  br label %merge

small:
  %b = sub i32 7, %x
  br label %merge

merge:
  %v = phi i32 [ %a, %big ], [ %b, %small ]
  %r = add i32 %v, 1
  ret i32 %r
}

define i32 @select_cmp(i32 %a, i32 %b) {
entry:
  %is_less = icmp slt i32 %a, %b
  %selected = select i1 %is_less, i32 %a, i32 %b
  ret i32 %selected
}

define internal i32 @bump(i32 %x) {
entry:
  %y = add i32 %x, 5
  ret i32 %y
}

define i32 @call_memory(ptr %src, ptr %dst) {
entry:
  %loaded = load i32, ptr %src, align 4
  %bumped = call i32 @bump(i32 %loaded)
  store i32 %bumped, ptr %dst, align 4
  %done = load i32, ptr %dst, align 4
  ret i32 %done
}

define i32 @gep_load(ptr %base, i32 %index) {
entry:
  %slot = getelementptr inbounds i32, ptr %base, i32 %index
  %value = load i32, ptr %slot, align 4
  ret i32 %value
}

define i32 @switch_score(i32 %tag, i32 %base) {
entry:
  switch i32 %tag, label %fallback [
    i32 0, label %zero
    i32 1, label %one
    i32 2, label %two
  ]

zero:
  %zero_v = add i32 %base, 10
  br label %done

one:
  %one_v = sub i32 %base, 3
  br label %done

two:
  %two_v = mul i32 %base, 2
  br label %done

fallback:
  %fallback_v = xor i32 %base, 5
  br label %done

done:
  %out = phi i32 [ %zero_v, %zero ], [ %one_v, %one ], [ %two_v, %two ], [ %fallback_v, %fallback ]
  ret i32 %out
}

define i16 @mixed_width(i8 %x, i32 %y) {
entry:
  %wide = zext i8 %x to i32
  %sum = add i32 %wide, %y
  %narrow = trunc i32 %sum to i16
  ret i16 %narrow
}

define float @float_mix(float %x, float %y) {
entry:
  %sum = fadd float %x, %y
  %large = fcmp ogt float %sum, 2.000000e+00
  %selected = select i1 %large, float %sum, float 2.000000e+00
  ret float %selected
}

define <2 x i32> @vector_mix(<2 x i32> %a, <2 x i32> %b) {
entry:
  %sum = add <2 x i32> %a, %b
  ret <2 x i32> %sum
}

define i32 @main() {
entry:
  %branch_big = call i32 @branch_phi(i32 12)
  %branch_small = call i32 @branch_phi(i32 3)
  %selected = call i32 @select_cmp(i32 7, i32 4)
  %mem = call i32 @call_memory(ptr @src.slot, ptr @dst.slot)
  %gep = call i32 @gep_load(ptr @arr.slot, i32 2)
  %switch_hit = call i32 @switch_score(i32 2, i32 7)
  %switch_miss = call i32 @switch_score(i32 9, i32 7)
  %mixed = call i16 @mixed_width(i8 25, i32 500)
  %float_value = call float @float_mix(float 1.500000e+00, float 7.500000e-01)
  %vector_value = call <2 x i32> @vector_mix(<2 x i32> <i32 1, i32 2>, <2 x i32> <i32 3, i32 4>)
  %lane0 = extractelement <2 x i32> %vector_value, i64 0
  %lane1 = extractelement <2 x i32> %vector_value, i64 1
  %ok1 = icmp eq i32 %branch_big, 20
  %ok2 = icmp eq i32 %branch_small, 5
  %ok3 = icmp eq i32 %selected, 4
  %ok4 = icmp eq i32 %mem, 42
  %ok5 = icmp eq i32 %gep, 21
  %ok6 = icmp eq i32 %switch_hit, 14
  %ok7 = icmp eq i32 %switch_miss, 2
  %ok8 = icmp eq i16 %mixed, 525
  %ok9 = fcmp oeq float %float_value, 2.250000e+00
  %ok10 = icmp eq i32 %lane0, 4
  %ok11 = icmp eq i32 %lane1, 6
  %ok12 = and i1 %ok1, %ok2
  %ok34 = and i1 %ok3, %ok4
  %ok56 = and i1 %ok5, %ok6
  %ok78 = and i1 %ok7, %ok8
  %ok910 = and i1 %ok9, %ok10
  %ok1011 = and i1 %ok910, %ok11
  %ok1234 = and i1 %ok12, %ok34
  %ok5678 = and i1 %ok56, %ok78
  %ok567811 = and i1 %ok5678, %ok1011
  %ok = and i1 %ok1234, %ok567811
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}

; CHECK-DAG: @__obf_vm_bc_i_{{[A-Za-z0-9_]+}} = private unnamed_addr constant [{{[0-9]+}} x i8] c"
; Retkey globals only for integer-returning functions (interleaved with bytecode globals).
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}} = private global i64 {{-?[0-9]+}}
; CHECK-DAG: @__obf_vm_s_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}} 0
; CHECK-DAG: @__obf_vm_s_{{[A-Za-z0-9_]+}} = private global i{{[0-9]+}} 0
; CHECK-DAG: @rt_core_ea = external externally_initialized global i64, align 8
; CHECK-NOT: @__obf_vm_retkey_float_mix
; CHECK-NOT: @__obf_vm_retkey_vector_mix
; CHECK-LABEL: define i32 @branch_phi(i32 %x)
; CHECK: entry.obf.vm.wrapper:
; CHECK: %branch_phi.obf.wrapper.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; CHECK: %branch_phi.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %branch_phi.obf.wrapper.target.seed.base = load i{{[0-9]+}}, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; CHECK: %branch_phi.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %branch_phi.obf.wrapper.target.key, i{{[0-9]+}} %branch_phi.obf.wrapper.target.base)
; CHECK: %branch_phi.obf.wrapper.real.int = sub i{{[0-9]+}} %branch_phi.obf.wrapper.target.value, %branch_phi.obf.wrapper.target.base
; CHECK: %branch_phi.obf.wrapper.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %branch_phi.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %branch_phi.obf.wrapper.decoded to ptr
; CHECK: %branch_phi.obf.wrapper.call{{[0-9]*}} = call i32 %branch_phi.obf.wrapper.indirect(i32 %x, i64 %branch_phi.obf.wrapper.token)
; CHECK: %branch_phi.obf.retkey = load i64, ptr @__obf_vm_retkey_i_{{[A-Za-z0-9_]+}}
; CHECK-LABEL: define <2 x i32> @vector_mix(<2 x i32> %a, <2 x i32> %b)
; CHECK: entry.obf.vm.wrapper:
; CHECK: %vector_mix.obf.wrapper.check = load i{{[0-9]+}}, ptr @__obf_vm_t_{{[A-Za-z0-9_]+}}
; CHECK: %vector_mix.obf.wrapper.target.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %vector_mix.obf.wrapper.target.seed.base = load i{{[0-9]+}}, ptr @__obf_vm_s_{{[A-Za-z0-9_]+}}
; CHECK: %vector_mix.obf.wrapper.target.seed.value = call i{{[0-9]+}} @__obf_vm_seed_resolve(i{{[0-9]+}} %vector_mix.obf.wrapper.target.key, i{{[0-9]+}} %vector_mix.obf.wrapper.target.base)
; CHECK: %vector_mix.obf.wrapper.real.int = sub i{{[0-9]+}} %vector_mix.obf.wrapper.target.value, %vector_mix.obf.wrapper.target.base
; CHECK: %vector_mix.obf.wrapper.key = load i{{[0-9]+}}, ptr @__obf_vm_k_{{[A-Za-z0-9_]+}}
; CHECK: %vector_mix.obf.wrapper.indirect = inttoptr i{{[0-9]+}} %vector_mix.obf.wrapper.decoded to ptr
; CHECK: %vector_mix.obf.wrapper.call{{[0-9]*}} = call <2 x i32> %vector_mix.obf.wrapper.indirect(<2 x i32> %a, <2 x i32> %b, i64 %vector_mix.obf.wrapper.token)
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %x, i64 %obf.hidden_token)
; CHECK: entry.obf.vm:
; CHECK: %obf.vm.state = alloca {
; CHECK: %obf.vm.dispatch.table = alloca [{{[0-9]+}} x i64]
; CHECK: %obf.entropy.cache.init{{[0-9]*}} = call { i64, i64 } @__obf_entropy_thunk_
; CHECK: %obf.entropy.pair{{[0-9]*}} = load { i64, i64 }, ptr %obf.entropy.cache, align 8
; CHECK: %obf.entropy.direct{{[0-9]*}} = extractvalue { i64, i64 } %obf.entropy.pair{{[0-9]*}}, 0
; CHECK: %obf.vm.integrity.ptr = getelementptr inbounds
; CHECK: %obf.vm.integrity.byte.ptr = getelementptr inbounds
; CHECK: %obf.vm.integrity.byte.window = load i32, ptr %obf.vm.integrity.byte.ptr, align 1
; CHECK: %obf.vm.integrity.byte = trunc i32 %obf.vm.integrity.byte.shr to i8
; CHECK: %obf.vm.integrity.fold = xor i64
; CHECK: indirectbr ptr
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(ptr %src, ptr %dst, i64 %obf.hidden_token)
; CHECK: %obf.vm.ptr.const = load ptr, ptr @__obf_vm_ptrconst_
; CHECK: %obf.vm.ptr.carrier{{[0-9]*}} =
; CHECK: %obf.vm.call = call i32 %obf.vm.ptr{{[0-9]*}}(i32
; CHECK: load i32, ptr
; CHECK: store i32
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(ptr %base, i32 %index, i64 %obf.hidden_token)
; CHECK: store i64 %obf.vm.ptr.carrier{{[0-9]*}}, ptr %obf.vm.state.slot.{{[0-9]+}}.{{[0-9]+}}
; CHECK: %obf.vm.slot.ptr.raw{{[0-9]*}} = load i64, ptr %obf.vm.state.slot.{{[0-9]+}}.{{[0-9]+}}
; CHECK: %obf.vm.slot.ptr.value{{[0-9]*}} = inttoptr i64 %obf.vm.slot.ptr.raw{{[0-9]*}} to ptr
; CHECK: getelementptr inbounds i32, ptr %{{[^,]+}}, i32 %obf.vm.slot
; CHECK: %obf.vm.ptr.carrier{{[0-9]*}} =
; CHECK-LABEL: define internal i32 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i32 %tag, i32 %base, i64 %obf.hidden_token)
; CHECK: vm.switch.default.
; CHECK-LABEL: define internal i16 @__obf_vm_i_{{[A-Za-z0-9_]+}}(i8 %x, i32 %y, i64 %obf.hidden_token)
; CHECK: vm.cast.exec.
; CHECK: %obf.vm.zext.bias =
; CHECK: %obf.vm.zext.wide = zext i8 %obf.vm.zext.bias to i32
; CHECK: %obf.vm.zext.signed.shl = shl i32 %{{[^,]+}}, 24
; CHECK: %obf.vm.zext.signed = ashr i32 %obf.vm.zext.signed.shl, 24
; CHECK: %obf.vm.zext = add i32
; CHECK: %obf.vm.trunc.mask = and i32 %{{[^,]+}}, 65535
; CHECK: %obf.vm.trunc = trunc i32 %obf.vm.trunc.mask to i16
; CHECK-LABEL: define internal float @__obf_vm_i_{{[A-Za-z0-9_]+}}(float %x, float %y, i64 %obf.hidden_token)
; CHECK: fcmp {{[a-z]+}} float
; CHECK-LABEL: define internal <2 x i32> @__obf_vm_i_{{[A-Za-z0-9_]+}}(<2 x i32> %a, <2 x i32> %b, i64 %obf.hidden_token)
; CHECK: add <2 x i32>
