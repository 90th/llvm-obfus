; REQUIRES: system-linux-x86-64, has-lld-llvm-match
; Retained routes and VM operand/result obligations must survive both backends.
;
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.full --lto full
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.thin --lto thin
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.full-vm --lto full --level vm
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.thin-vm --lto thin --level vm
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.full-strong --lto full --level strong_vm
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.thin-strong --lto thin --level strong_vm
