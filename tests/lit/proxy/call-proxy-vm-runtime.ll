; REQUIRES: system-linux-x86-64 || system-windows-x86-64
; Both resolver paths must preserve the encoded-result/caller-decode contract.
;
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.vm --level vm
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.strong --level strong_vm
