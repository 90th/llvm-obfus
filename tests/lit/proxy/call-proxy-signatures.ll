; REQUIRES: system-linux-x86-64 || system-windows-x86-64
; Each executable checks exact lane, aggregate, and sret stores in main.
; The native control distinguishes invalid ABI fixtures from emitter failures.
;
; RUN: %python %S/../Inputs/call_proxy_signatures.py --wrapper %obf_clang --clang %raw_clang --source %S/../Inputs/call_proxy_signatures.ir --runtime %obf_runtime --work %t
