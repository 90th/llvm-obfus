; REQUIRES: system-linux-x86-64
; Corrupt each defined field after first-hop capture in a valid live context.
; Reject wrong-node entry, skipped transitions, and replay after consumption.
;
; RUN: %python %S/../Inputs/call_proxy_corruption.py --wrapper %obf_clang --clang %raw_clang --runtime %obf_runtime --source %S/../Inputs/call_proxy_corruption.ir --work %t
