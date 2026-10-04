; REQUIRES: system-linux-x86-64 || system-windows-x86-64
;
; Native O0 C++ calls use the Windows x64 aggregate ABI, including on Linux via
; ms_abi. Check exact returned values, observable memory effects, and VM emission
; rather than relying on the frontend's incidental IR spelling.
; RUN: %cmake -E env OBF_COVERAGE_REPORT=%t.native.json %obf_clangxx -std=c++17 -O0 -fexceptions -fcxx-exceptions --obf-config=%S/../Inputs/vm-o0-aggregates.yaml %S/../Inputs/vm-o0-aggregates.cpp -o %t.native.exe
; RUN: %t.native.exe
; RUN: %python -c "import json,sys; d=json.load(open(sys.argv[1])); names={'obf_o0_param8','obf_o0_return8','obf_o0_two_floats'}; e=[x for x in d['emission'] if x['mechanism']=='vm' and x['status']=='emitted' and x['scope']=='whole_function']; assert names <= {x['owner'] for x in e}; assert all(any(x['owner']==n and x['policy']['level']=='strong_vm' and x['policy']['allow_vm'] for x in d['requested_policy']) for n in names)" %t.native.json
;
; A real stack address escapes through a global and an opaque native observer.
; Scalar replacement must not turn this into supported VM stack execution.
; RUN: %python %S/../Inputs/expect_failure.py %obf_clangxx -std=c++17 -O0 -fexceptions -fcxx-exceptions -DOBF_TEST_ESCAPE --obf-config=%S/../Inputs/vm-o0-aggregates.yaml -c %S/../Inputs/vm-o0-aggregates.cpp -o %t.escape.o 2>&1 | %FileCheck %s --check-prefix=ESCAPE
;
; Direct obf-vm is intentionally not a normalization pipeline. Its existing
; alloca rejection is separate from native/managed O0 preparation.
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-o0-aggregates.yaml -passes='obf-coverage-start,obf-vm,obf-coverage-report' -disable-output %s > %t.direct.json
; RUN: %python -c "import json,sys; d=json.load(open(sys.argv[1])); assert any(x['owner']=='obf_o0_direct_alloca' and x['mechanism']=='vm' and x['status']=='skipped' and 'alloca' in x['reason'] for x in d['admission']); assert not any(x['mechanism']=='vm' and x['status']=='emitted' for x in d['emission'])" %t.direct.json
;
; Cache host function analyses after coverage-start (which invalidates analyses),
; then query them after each preparation. Deleted stack stores must not remain
; in the cached MemorySSA chain for the surviving effect store. Check that chain
; explicitly because MemorySSA verification is disabled in assertion-free LLVM.
; Both the explicit and managed postlink O0 routes execute the same exact-value
; consumer, including successive calls with cumulative memory effects.
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-o0-aggregates.yaml -passes='obf-coverage-start,function(require<domtree>,require<memoryssa>),obf-prepare-o0,function(verify<domtree>,verify<memoryssa>,print<memoryssa>),obf-prepare-o0,function(verify<domtree>,verify<memoryssa>,print<memoryssa>),obf-vm,obf-coverage-report,verify' -S %s -o %t.prepared.ll > %t.prepared.json 2> %t.prepared.mssa
; RUN: %FileCheck %s --check-prefix=PREPARED-MSSA < %t.prepared.mssa
; RUN: %python -c "import json,sys; d=json.load(open(sys.argv[1])); assert any(x['owner']=='obf_o0_direct_alloca' and x['mechanism']=='vm' and x['status']=='emitted' and x['scope']=='whole_function' for x in d['emission'])" %t.prepared.json
; RUN: %raw_clangxx -O0 %t.prepared.ll %obf_runtime -o %t.prepared.exe
; RUN: %t.prepared.exe
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-o0-aggregates.yaml -passes='function(require<domtree>,require<memoryssa>),lto<O0>,function(verify<domtree>,verify<memoryssa>),verify' -S %s -o %t.lto.ll
; RUN: %raw_clangxx -O0 %t.lto.ll %obf_runtime -o %t.lto.exe
; RUN: %t.lto.exe
;
; PREPARED-MSSA-LABEL: MemorySSA for function: obf_o0_direct_alloca
; PREPARED-MSSA: ; {{[0-9]+}} = MemoryDef(liveOnEntry)
; PREPARED-MSSA-NEXT: store i64 %new_effect, ptr %effect, align 8
; PREPARED-MSSA-LABEL: MemorySSA for function: obf_o0_direct_alloca
; PREPARED-MSSA: ; {{[0-9]+}} = MemoryDef(liveOnEntry)
; PREPARED-MSSA-NEXT: store i64 %new_effect, ptr %effect, align 8
; ESCAPE: strong_vm invariant violation: function obf_o0_escaping_buffer was not virtualized
; ESCAPE-SAME: alloca

%S8 = type { i64 }

define i64 @obf_o0_direct_alloca(i64 %value, ptr %effect) noinline optnone {
entry:
  %aggregate = alloca %S8, align 8
  %value_slot = alloca i64, align 8
  store i64 %value, ptr %value_slot, align 8
  %stored_value = load i64, ptr %value_slot, align 8
  %field = getelementptr inbounds %S8, ptr %aggregate, i32 0, i32 0
  store i64 %stored_value, ptr %field, align 8
  %loaded = load i64, ptr %aggregate, align 8
  %old_effect = load i64, ptr %effect, align 8
  %new_effect = add i64 %old_effect, %loaded
  store i64 %new_effect, ptr %effect, align 8
  %result = add i64 %loaded, 17
  ret i64 %result
}

define i32 @main() {
entry:
  %effect = alloca i64, align 8
  store i64 5, ptr %effect, align 8
  %result = call i64 @obf_o0_direct_alloca(i64 37, ptr %effect)
  %observed_effect = load volatile i64, ptr %effect, align 8
  %second_result = call i64 @obf_o0_direct_alloca(i64 -9, ptr %effect)
  %second_effect = load volatile i64, ptr %effect, align 8
  %result_ok = icmp eq i64 %result, 54
  %effect_ok = icmp eq i64 %observed_effect, 42
  %first_ok = and i1 %result_ok, %effect_ok
  %second_result_ok = icmp eq i64 %second_result, 8
  %second_effect_ok = icmp eq i64 %second_effect, 33
  %second_ok = and i1 %second_result_ok, %second_effect_ok
  %ok = and i1 %first_ok, %second_ok
  %exit = select i1 %ok, i32 0, i32 1
  ret i32 %exit
}
