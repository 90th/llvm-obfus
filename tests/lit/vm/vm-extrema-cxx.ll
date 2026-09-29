; RUN: %raw_clang -x c++ -std=c++20 -O2 -S -emit-llvm %S/../Inputs/vm-extrema-cxx.cpp -o %t.optimized.ll
; RUN: %FileCheck %s --check-prefix=OPTIMIZED < %t.optimized.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-extrema-cxx.yaml -passes='obf-safe-pipeline,verify' -S %t.optimized.ll -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=SAFE < %t.protected.ll
; RUN: %lli %t.optimized.ll
; RUN: %lli %t.protected.ll

; Clang's optimized std::max emits intrinsics before the production VM pass.
; OPTIMIZED-LABEL: define{{.*}} @cpp_smax(
; OPTIMIZED: call i32 @llvm.smax.i32
; OPTIMIZED-LABEL: define{{.*}} @cpp_umax(
; OPTIMIZED: call i32 @llvm.umax.i32

; The protected entrypoints must dispatch indirectly into the VM, not call
; the native max intrinsics left in the pre-obfuscation IR.
; SAFE-LABEL: define{{.*}} @cpp_smax(
; SAFE: call i32 %
; SAFE-NOT: call i32 @llvm.smax.i32
; SAFE-LABEL: define{{.*}} @cpp_umax(
; SAFE: call i32 %
; SAFE-NOT: call i32 @llvm.umax.i32
