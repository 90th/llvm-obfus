; REQUIRES: system-linux-x86-64
; Real calls retain CET instrumentation and permit outward unwind with frames.
; Each Linux image is checked for forbidden TEXTREL dynamic entries.
;
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.pie --hops 4 --cet
; RUN: %python %S/../Inputs/call_proxy_runtime.py --wrapper %obf_clangxx --clang %raw_clang --source %S/../Inputs/call_proxy_runtime.cpp --work %t.pic --hops 4 --cet --shared
