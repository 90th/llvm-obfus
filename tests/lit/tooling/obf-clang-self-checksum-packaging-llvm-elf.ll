; REQUIRES: system-linux-x86-64, has-self-checksum-binder, has-llvm-elf-packaging
; RUN: %python %S/../Inputs/self_checksum_elf_packaging.py --clang %raw_clang --wrapper %obf_clang --binder %obf_checksum_bind --runtime %obf_runtime --strip %llvm_packaging_strip --objcopy %llvm_packaging_objcopy --work %t.llvm
;
; Run the same native record/sample/binding contracts with LLVM strip/objcopy.
; Missing LLVM packaging tools make this test unsupported, not a successful skip.
