; REQUIRES: system-windows-x86-64, has-self-checksum-binder
;
; Compile the provider and consumer independently with the configured Clang g++
; host. The harness uses shared CRT startup, the configured obf-clang++ runtime,
; serial compilation/execution, and one isolated retained evidence directory.
; Compiler emission reports corroborate ABI probes; they are not VM-entry traces.
; The harness checks native values, effects, exception payloads, cleanup, exports,
; and compiler policy reports. Its output is diagnostic, not a test oracle.
; RUN: %python %S/../Inputs/cpp_dll_abi.py --wrapper %obf_clangxx --clang %raw_clang --work %t
;

define void @dummy() {
entry:
  ret void
}
