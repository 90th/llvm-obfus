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

; CHECK-LABEL: define i32 @branch_phi(i32 %x)
; CHECK: entry.obf.vm:
; CHECK: dispatch.obf.vm:
; CHECK: br i1
; CHECK-LABEL: define i32 @call_memory(ptr %src, ptr %dst)
; CHECK: call i32 @bump(i32
; CHECK: load i32, ptr
; CHECK: store i32
; CHECK-LABEL: define i32 @gep_load(ptr %base, i32 %index)
; CHECK: getelementptr inbounds i32, ptr
; CHECK-LABEL: define i32 @switch_score(i32 %tag, i32 %base)
; CHECK: vm.switch.default.
; CHECK-LABEL: define float @float_mix(float %x, float %y)
; CHECK: fcmp ogt float
; CHECK-LABEL: define <2 x i32> @vector_mix(<2 x i32> %a, <2 x i32> %b)
; CHECK: add <2 x i32>
