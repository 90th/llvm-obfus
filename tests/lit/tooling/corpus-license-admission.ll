; REQUIRES: system-linux-x86-64 || system-windows-x86-64
;
; Exercise the actual corpus source and protection profile through the same
; post-IR pipeline as the corpus benchmark targets.
; RUN: %raw_clangxx -std=c++17 -O1 -fno-inline -fno-inline-functions -S -emit-llvm %S/../../../benchmarks/corpus/license_demo.cpp -o %t.baseline.ll
; RUN: %cmake -E env "OBF_CONFIG=%S/../../../benchmarks/config/license_demo.yaml" OBF_SEED=424242 %opt -load-pass-plugin %obf_plugin -passes=obf-safe-pipeline -S %t.baseline.ll -o %t.protected.ll
; RUN: %raw_clangxx -O0 %t.baseline.ll -o %t.baseline.exe
; RUN: %raw_clangxx -O0 %t.protected.ll %obf_runtime -o %t.protected.exe
; RUN: %python %S/../Inputs/corpus-license-admission.py %t.baseline.exe %t.protected.exe

define void @dummy() {
  ret void
}
