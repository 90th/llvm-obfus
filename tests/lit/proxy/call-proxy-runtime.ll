; REQUIRES: system-linux-x86-64 || system-windows-x86-64
; Native results and effects cover stack arguments, aggregate forwarding,
; floating-point results, outward unwind, reentry, loop slots, and concurrency.
; Mutual musttail recursion remains live through frontend optimization.
;
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.two --hops 2
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.eight --hops 8
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.shared --hops 4 --shared
