; REQUIRES: system-linux-x86-64
;
; Constant encoding does not currently select vector constants, so vector
; opaque-zero integration is intentionally omitted rather than copied by hand.
; shape_mix exercises the protected scalar delivery path.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml --obf-seed=1 -passes=obf-constant-encode -S %s -o %t.seed1.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml --obf-seed=2 -passes=obf-constant-encode -S %s -o %t.seed2.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/mba-entropy-shape-diversity.yaml --obf-seed=3 -passes=obf-constant-encode -S %s -o %t.seed3.ll
; RUN: %FileCheck %s --check-prefix=STRUCT < %t.seed1.ll
; RUN: %opt -passes=verify -disable-output %t.seed1.ll
; RUN: %opt -passes=verify -disable-output %t.seed2.ll
; RUN: %opt -passes=verify -disable-output %t.seed3.ll
; RUN: %raw_lli %t.seed1.ll
; RUN: %raw_lli %t.seed1.ll poison
; RUN: %raw_lli %t.seed1.ll poison extra
; RUN: %raw_lli %t.seed2.ll
; RUN: %raw_lli %t.seed3.ll
; RUN: %opt -O2 -S %t.seed1.ll -o %t.seed1.o2.ll
; RUN: %opt -passes=verify -disable-output %t.seed1.o2.ll
; RUN: %raw_lli %t.seed1.o2.ll
; RUN: %raw_lli %t.seed1.o2.ll poison
; RUN: %raw_lli %t.seed1.o2.ll poison extra
; RUN: %python %S/../Inputs/mba-shape-native-extract.py %t.seed1.ll %t.native-shapes.ll
; RUN: %llc -O2 -filetype=asm %t.native-shapes.ll -o %t.native-shapes.s
; RUN: %FileCheck %s --check-prefix=BITPART --check-prefix=CMPSEL < %t.native-shapes.s
; RUN: %python %S/../Inputs/mba-shape-native-extract.py --zero-family=bit_partition_pair %t.seed1.ll %t.native-bit-zero.ll
; RUN: %llc -O2 -filetype=asm %t.native-bit-zero.ll -o %t.native-bit-zero.s
; RUN: not %FileCheck %s --check-prefix=BITPART < %t.native-bit-zero.s
; RUN: %python %S/../Inputs/mba-shape-native-extract.py --zero-family=cmp_select_pair %t.seed1.ll %t.native-cmp-zero.ll
; RUN: %llc -O2 -filetype=asm %t.native-cmp-zero.ll -o %t.native-cmp-zero.s
; RUN: not %FileCheck %s --check-prefix=CMPSEL < %t.native-cmp-zero.s
; RUN: %python -c "import pathlib,re,sys; p=pathlib.Path(sys.argv[1]); text=p.read_text(); text=re.sub(r'(?ms)^define \{ i64, i64 \} @rt_core_ep[0-4]\(\) \{\n.*?^\}\n','',text); text=re.sub(r'(?m)^@rt_core_ea = .*\n','',text,count=1); decl='declare { i64, i64 } @rt_core_ep0()\ndeclare { i64, i64 } @rt_core_ep1()\ndeclare { i64, i64 } @rt_core_ep2()\ndeclare { i64, i64 } @rt_core_ep3()\ndeclare { i64, i64 } @rt_core_ep4()\n'; pos=text.find('\n',text.find('target triple')); text=text[:pos+1]+decl+text[pos+1:]; pathlib.Path(sys.argv[2]).write_text(text)" %t.seed1.ll %t.native.ll
; RUN: %llc -O2 -filetype=asm %t.native.ll -o %t.full.s
; RUN: %python %S/../Inputs/mba-shape-native-extract.py --mutate-module --zero-family=bit_partition_pair %t.native.ll %t.full-bit-zero.ll
; RUN: %llc -O2 -filetype=asm %t.full-bit-zero.ll -o %t.full-bit-zero.s
; RUN: %python %S/../Inputs/mba-shape-native-extract.py --mutate-module --zero-family=cmp_select_pair %t.native.ll %t.full-cmp-zero.ll
; RUN: %llc -O2 -filetype=asm %t.full-cmp-zero.ll -o %t.full-cmp-zero.s
; RUN: %python -c "import pathlib,re,sys; pat=re.compile(r'(?ms)^shape_mix:.*?^\.Lfunc_end'); bodies=[pat.search(pathlib.Path(p).read_text()).group() for p in sys.argv[1:]]; assert bodies[0]!=bodies[1] and bodies[0]!=bodies[2]" %t.full.s %t.full-bit-zero.s %t.full-cmp-zero.s
; RUN: %llc -O2 -filetype=obj %t.native.ll -o %t.native.o
; RUN: %raw_clang %t.native.o %obf_runtime -o %t.native
; RUN: %t.native
; RUN: %t.native native
; RUN: %t.native native extra
;
; STRUCT-LABEL: define i64 @shape_mix(i64 %x)
; STRUCT-DAG: obf.mba.zero.bit_partition_pair.input{{[0-9]*}} = xor i8
; STRUCT-DAG: obf.mba.zero.bit_partition_pair.input{{[0-9]*}} = xor i16
; STRUCT-DAG: obf.mba.zero.bit_partition_pair.input{{[0-9]*}} = xor i32
; STRUCT-DAG: obf.mba.zero.bit_partition_pair.input{{[0-9]*}} = xor i64
; STRUCT-DAG: obf.mba.zero.cmp_select_pair.zero.alt{{[0-9]*}} = and
; STRUCT-DAG: obf.mba.zero.bit_partition_pair.rhs{{[0-9]*}} = xor
; STRUCT-DAG: obf.mba.zero.cmp_select_pair.zero.eq{{[0-9]*}} = sub
; The extracted slices return live i64 opaque-zero roots from seed1's
; protected result. Zeroing either family removes its native arithmetic.
; BITPART-LABEL: bit_partition_pair_live:
; BITPART: xorq
; BITPART: orq
; BITPART: andq
; BITPART: subq
; BITPART: xorq
; BITPART: xorq
; CMPSEL-LABEL: cmp_select_pair_live:
; CMPSEL: orq
; CMPSEL: subq
; CMPSEL: cmov


target triple = "x86_64-unknown-linux-gnu"
@rt_core_ea = global i64 0, align 8
; The fixed seeds route one run through each cmp-select mode: ep0 supplies a
; concrete-equal pair, ep2 supplies poison, ep3 supplies a concrete-unequal
; pair after the first call in a process, and ep4 remains undef.



define { i64, i64 } @rt_core_ep0() {
entry:
  %mode = load i64, ptr @rt_core_ea, align 8
  %next = add i64 %mode, 1
  store i64 %next, ptr @rt_core_ea, align 8
  %is.first = icmp eq i64 %mode, 0
  %direct = select i1 %is.first, i64 3689348814741910323, i64 1229782938247303441
  %indirect = select i1 %is.first, i64 3689348814741910323, i64 2459565876494606882
  %pair.direct = insertvalue { i64, i64 } undef, i64 %direct, 0
  %pair = insertvalue { i64, i64 } %pair.direct, i64 %indirect, 1
  ret { i64, i64 } %pair
}

define { i64, i64 } @rt_core_ep1() {
entry:
  ret { i64, i64 } undef
}

define { i64, i64 } @rt_core_ep2() {
entry:
  %mode = load i64, ptr @rt_core_ea, align 8
  %next = add i64 %mode, 1
  store i64 %next, ptr @rt_core_ea, align 8
  ret { i64, i64 } poison
}

define { i64, i64 } @rt_core_ep3() {
entry:
  %mode = load i64, ptr @rt_core_ea, align 8
  %next = add i64 %mode, 1
  store i64 %next, ptr @rt_core_ea, align 8
  %is.first = icmp eq i64 %mode, 0
  %direct = select i1 %is.first, i64 poison, i64 1229782938247303441
  %indirect = select i1 %is.first, i64 poison, i64 2459565876494606882
  %pair.direct = insertvalue { i64, i64 } undef, i64 %direct, 0
  %pair = insertvalue { i64, i64 } %pair.direct, i64 %indirect, 1
  ret { i64, i64 } %pair
}

define { i64, i64 } @rt_core_ep4() {
entry:
  ret { i64, i64 } undef
}

; Every scalar width is exercised by a separately typed constant operation.
define i64 @shape_mix(i64 %x) noinline {
entry:
  %x8 = trunc i64 %x to i8
  %v8 = add i8 %x8, 17
  %x16 = trunc i64 %x to i16
  %v16 = xor i16 %x16, 4660
  %x32 = trunc i64 %x to i32
  %v32 = sub i32 %x32, 1234567
  %v64 = add i64 %x, 281474976710677
  %e8 = zext i8 %v8 to i64
  %e16 = zext i16 %v16 to i64
  %e32 = zext i32 %v32 to i64
  %sum1 = add i64 %e8, %e16
  %sum2 = add i64 %sum1, %e32
  %sum3 = add i64 %sum2, %v64
  ret i64 %sum3
}

define i32 @main(i32 %argc, ptr %argv) {
entry:
  %x = zext i32 %argc to i64
  %value = call i64 @shape_mix(i64 %x)
  %is.argc1 = icmp eq i32 %argc, 1
  %is.argc2 = icmp eq i32 %argc, 2
  %expected.argc23 = select i1 %is.argc2, i64 281479270448091, i64 281479270448095
  %expected = select i1 %is.argc1, i64 281479270448087, i64 %expected.argc23
  %ok = icmp eq i64 %value, %expected
  %ret = select i1 %ok, i32 0, i32 1
  ret i32 %ret
}
