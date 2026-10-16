; REQUIRES: system-linux-x86-64
; Released same-config output must not receive nested proxy routes. Reconfigure
; from original IR instead of accepting different seed/options on released output.
;
; RUN: %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-native.yaml -passes='obf-safe-pipeline,obf-safe-pipeline,verify' -S %S/../Inputs/call_proxy_corruption.ir -o %t.ll
; RUN: %raw_clang %t.ll %obf_runtime -o %t.exe
; RUN: %t.exe
; RUN: not --crash %opt -load-pass-plugin %obf_plugin --obf-config=%S/../Inputs/call-proxy-native.yaml --obf-seed=7 -passes=obf-safe-pipeline -disable-output %t.ll 2>&1 | %FileCheck %s
;
; CHECK: incompatible config/seed for completed native pipeline
