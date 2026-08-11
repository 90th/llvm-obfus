; REQUIRES: has-tinygo-wrapper-host
;
; This simulates an executable suffix only while configuring the native Linux
; wrapper. It verifies that the default obf-bc path remains the unsuffixed
; configure_file output; it does not claim Windows TinyGo support.
;
; RUN: %cmake "-DTEST_ROOT=%t.suffix-contract" "-DWRAPPER_TEMPLATE=%S/../../../tools/obf-tinygo/obf-tinygo.py.in" "-DFAKE_TOOL=%S/../Inputs/obf-tinygo-fake-tools.py" "-DPYTHON_EXECUTABLE=%python" "-DTINYGO_CONFIG=%S/../Inputs/obf-tinygo-config.yaml" "-DGO_SOURCE=%S/../Inputs/obf-tinygo-numeric.go" "-DSIMULATED_EXECUTABLE_SUFFIX=.exe" "-DLLVM_HOST_TRIPLE=%llvm_host_triple" -P "%S/../Inputs/obf-tinygo-suffix-contract.cmake"
