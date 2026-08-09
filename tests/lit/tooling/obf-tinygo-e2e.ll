; REQUIRES: has-tinygo-041-go-supported-llvm20, has-lld-21, system-linux
;
; This is deliberately the only real TinyGo test. It uses native Linux ELF,
; both supported GC modes, no scheduler runtime services, and a numeric-only
; program. It inspects the protected BC from the conservative-GC invocation.
;
; RUN: rm -rf %t.cache && mkdir -p %t.cache
; RUN: env XDG_CACHE_HOME=%t.cache timeout 180 %raw_tinygo build -scheduler=none -gc=conservative -o %t.baseline %S/../Inputs/obf-tinygo-numeric.go
; RUN: env XDG_CACHE_HOME=%t.cache timeout 180 %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml --obf-save-bc=%t.protected.bc build -scheduler=none -gc=conservative -o %t.protected %S/../Inputs/obf-tinygo-numeric.go 2>&1 | tee %t.wrapper.log | %FileCheck %s --check-prefix=PROVENANCE
; RUN: %python %S/../Inputs/obf-tinygo-assert.py chain %t.wrapper.log %obf_runtime
; RUN: %opt -S %t.protected.bc -o %t.protected.ll
; RUN: %FileCheck %s --check-prefix=BC --implicit-check-not=@llvm.global_ctors < %t.protected.ll
; RUN: %t.baseline > %t.baseline.stdout 2>&1
; RUN: %t.protected > %t.protected.stdout 2>&1
; RUN: cmp %t.baseline.stdout %t.protected.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.protected.stdout
; RUN: %llvm_nm --defined-only --extern-only %t.protected | %FileCheck %s --check-prefix=SYMBOLS --implicit-check-not=__obf_
; RUN: env XDG_CACHE_HOME=%t.cache timeout 180 %raw_tinygo build -scheduler=none -gc=none -o %t.none.baseline %S/../Inputs/obf-tinygo-numeric.go
; RUN: env XDG_CACHE_HOME=%t.cache timeout 180 %obf_tinygo --obf-config=%S/../Inputs/obf-tinygo-config.yaml build -scheduler=none -gc=none -o %t.none.protected %S/../Inputs/obf-tinygo-numeric.go
; RUN: %t.none.baseline > %t.none.baseline.stdout 2>&1
; RUN: %t.none.protected > %t.none.protected.stdout 2>&1
; RUN: cmp %t.none.baseline.stdout %t.none.protected.stdout
; RUN: %FileCheck %s --check-prefix=RESULT < %t.none.protected.stdout
;
; PROVENANCE: obf-tinygo: provenance {{.*"llc_argv":.*"-mcpu=[^"]+".*"-mattr=[^"]+".*"protected_bc":.*"relink_argv":.*"ld.lld".*}}
; BC-DAG: @rt_core_ea = external externally_initialized global i64
; BC-LABEL: define{{.*}} i64 @protected_value(i64
; BC: alloca { i64, i64 }, align {{4|8}}
; BC: freeze i64
; RESULT: 767
; SYMBOLS: protected_value
