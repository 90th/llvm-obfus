; REQUIRES: system-windows-x86-64, has-self-checksum-binder
;
; O0/O2 x vm/strong_vm use native C++ DLL and shared CRT startup. A raw host
; checks exact construction, failed local initialization/retry, native EH/SEH,
; TLS/FLS cleanup, destructor LIFO, failed attach, and three fresh unload cycles.
; Ordinary FROM_ADDRESS references protect live TLS and in-flight exported work;
; PIN is not used. An explicitly drained FLS thread outlives actual unmapping.
; ExitProcess checks main-thread cleanup with a dormant native-TLS worker.
; Independent raw DLL arithmetic controls are compared with all protected rows.
; Compiler ledgers check VM emission, authenticated text, checksums, and native
; EH/SEH fallback. PE unwind pointers and live RtlLookupFunctionEntry are checked.
; result.json and commands.jsonl remain in isolated TEMP evidence directories.
; RUN: %python %S/../Inputs/cpp_pe_shared_lifecycle.py --wrapper %obf_clangxx --clang %raw_clang --binder %obf_checksum_bind
;
define void @dummy() {
entry:
  ret void
}
