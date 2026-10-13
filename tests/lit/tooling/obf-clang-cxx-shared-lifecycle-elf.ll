; REQUIRES: system-linux-x86-64, system-glibc, has-lld-llvm-match, has-self-checksum-binder
;
; O0/O2 x vm/strong_vm check normal C++ static initialization, initializer
; exception cleanup and retry, TLS destruction, and final static destruction.
; Independent raw controls and a raw host check exact event order and effects.
; Joined unload, TLS retention, and explicit NODELETE have separate mapping
; observations. Each ordinary case proves actual final unload and fresh reload.
; Protected lifecycle calls use authenticated text and bound code checksums.
; Local EH functions retain native fallbacks. Evidence stays in isolated /tmp
; directories, including compiler ledgers and complete native command outputs.
; RUN: %python %S/../Inputs/cpp_elf_shared_lifecycle.py --wrapper %obf_clangxx --clang %raw_clang --binder %obf_checksum_bind
;
define void @dummy() {
entry:
  ret void
}
