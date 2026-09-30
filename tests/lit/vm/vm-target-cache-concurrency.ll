; REQUIRES: system-linux
; RUN: %raw_clang -O1 -pthread -DOBF_CACHE_TARGETS -S -emit-llvm %S/../Inputs/vm-target-cache-concurrency.c -o %t.input.ll
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/vm-target-cache-concurrency.yaml -passes='obf-vm,verify' -S %t.input.ll -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=IR < %t.protected.ll
; RUN: %raw_clang -O1 -pthread %S/../Inputs/vm-target-cache-concurrency.c %t.protected.ll %obf_runtime -o %t.protected
; RUN: %t.protected
; RUN: %raw_clang -O1 -pthread -S -emit-llvm %S/../Inputs/vm-target-cache-concurrency.c -o %t.harness.ll
; RUN: %FileCheck %s --check-prefix=WRAPPER < %t.harness.ll

; IR-DAG: @[[TARGET:__obf_vm_t_[A-Za-z0-9_]+]] = private global i{{[0-9]+}} {{-?[0-9]+}}, align [[TARGET_ALIGN:[0-9]+]]
; IR-LABEL: define{{.*}} @cache_target(
; IR: %cache_target.obf.wrapper.check = load atomic i{{[0-9]+}}, ptr @[[TARGET]] monotonic, align [[TARGET_ALIGN]]
; IR: store atomic i{{[0-9]+}} %cache_target.obf.wrapper.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET]] monotonic, align [[TARGET_ALIGN]]
; IR-LABEL: define{{.*}} @callsite_user(
; IR: %cache_target.obf.check = load atomic i{{[0-9]+}}, ptr @[[TARGET]] monotonic, align [[TARGET_ALIGN]]
; IR: store atomic i{{[0-9]+}} %cache_target.obf.resolved{{(\.poison[0-9]*)?}}, ptr @[[TARGET]] monotonic, align [[TARGET_ALIGN]]
; IR: call i32 %cache_target.obf.indirect(i32 {{%[^,]+}}, i64 %cache_target.obf.call.token)
; WRAPPER-LABEL: define{{.*}} @run_thread(
; WRAPPER: %[[WRAPPER:[A-Za-z0-9_.]+]] = load volatile ptr, ptr @g_wrapper_target
; WRAPPER: call i32 %[[WRAPPER]](
