; REQUIRES: system-linux
; RUN: %raw_clang -O1 -fno-inline -fno-inline-functions -fno-builtin-strcmp -emit-llvm -c %S/../Inputs/obf-bc-e2e.c -o %t.input.bc
; RUN: umask 022 && %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml --obf-seed=424242 %t.input.bc -o %t.fresh.bc
; RUN: %python -c "import pathlib,stat,sys; sys.exit(0 if stat.S_IMODE(pathlib.Path(sys.argv[1]).stat().st_mode) == 0o644 else 1)" %t.fresh.bc
; RUN: printf 'mode sentinel\n' > %t.existing.bc
; RUN: chmod 0640 %t.existing.bc
; RUN: umask 077 && %obf_bc --obf-config=%S/../Inputs/obf-bc-e2e.yaml --obf-seed=424242 %t.input.bc -o %t.existing.bc
; RUN: %python -c "import pathlib,stat,sys; sys.exit(0 if stat.S_IMODE(pathlib.Path(sys.argv[1]).stat().st_mode) == 0o640 else 1)" %t.existing.bc
;
; Linux mode checks are isolated from the unconditional E2E test: fresh output
; honors the invoking umask, and replacement preserves an existing destination's
; permission bits even when that invocation has a different umask.

define void @dummy() {
entry:
  ret void
}
