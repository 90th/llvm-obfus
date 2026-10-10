; REQUIRES: system-linux-x86-64, has-lld-llvm-match, has-self-checksum-binder
;
; Native controls select a strong GLOBAL provider before loading the target.
; Same-TU calls must retain ELF preemption for weak and default-visible targets.
; Hidden and protected targets must retain their own implementation instead.
; Check exact results and cumulative effects through direct and callback calls.
; O0/O2 x GNU BFD/LLD x vm/strong_vm x reports on/off.
; RUN: %python %S/../Inputs/vm_elf_symbol_resolution.py --wrapper %obf_clang --clang %raw_clang --work %t
;
define void @dummy() {
entry:
  ret void
}
