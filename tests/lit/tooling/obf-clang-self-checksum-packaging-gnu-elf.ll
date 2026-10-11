; REQUIRES: system-linux-x86-64, has-self-checksum-binder, has-gnu-elf-packaging
; RUN: %python %S/../Inputs/self_checksum_elf_packaging.py --clang %raw_clang --wrapper %obf_clang --binder %obf_checksum_bind --runtime %obf_runtime --strip %gnu_packaging_strip --objcopy %gnu_packaging_objcopy --work %t.gnu
;
; Each exec, PIE, and dlopen DSO operation starts with an independent pristine
; UNBOUND or wrapper-BOUND copy. Deployed native calls check exact uint64 returns
; and cumulative effects against a raw independent TU on 512 deterministic inputs.
; Debug splitting retains raw TU debug data without changing protected cleanup.
; Rejected late headers and bound sample mismatches must preserve the input file.
