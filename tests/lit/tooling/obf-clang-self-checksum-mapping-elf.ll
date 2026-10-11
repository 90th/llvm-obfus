; REQUIRES: system-linux-x86-64, has-self-checksum-binder
; RUN: %obf_clang -O0 -no-pie --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.exec
; RUN: %python %S/../Inputs/self_checksum_elf_mapping.py --binder %obf_checksum_bind --image %t.exec
; RUN: %obf_clang -O0 -fPIE -pie --obf-config=%S/../Inputs/self-checksum-bound.yaml %S/../Inputs/obf-clang-self-checksum.c -o %t.pie
; RUN: %python %S/../Inputs/self_checksum_elf_mapping.py --binder %obf_checksum_bind --image %t.pie
;
; Section headers and PT_LOAD must identify the same physical record bytes.
; Valid UNBOUND images bind and execute; repeated binding preserves valid BOUND images.
; Detached UNBOUND and BOUND copies retain valid headers and sample hashes, but both
; probe and bind must reject their unloaded metadata without changing the image.
; An overflowing mapping whose unchecked sum would match the section offset must
; also be rejected non-destructively, without changing the executable sample mapping.
