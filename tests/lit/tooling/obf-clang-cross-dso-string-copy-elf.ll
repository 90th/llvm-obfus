; REQUIRES: system-linux-x86-64, system-glibc, has-lld-llvm-match
;
; O0/O2 x vm/strong_vm consumers read caller-owned copies from two independent
; native producers. Raw controls check exact strings, capacities, statuses, and
; effects. The host unloads each producer and proves actual mapping removal
; before it consumes saved copies. A v2-only producer must not resolve v1.
; Lazy and constructor-backed producers authenticate each successful copy.
; Native data-only corruption follows a valid first copy. Shared destinations
; and effects must stay unchanged when the next copy traps. Queries and errors
; must return ordinary statuses without certifying corrupted data. Cold lazy
; corruption checks the same rule before the first successful copy.
; Narrow rejection cases keep strict static ownership and raw-manifest rules.
; All compiler ledgers, commands, native outcomes, and scratch stay under /tmp.
; RUN: %python %S/../Inputs/cross_dso_string_copy.py --wrapper %obf_clang --clang %raw_clang
;
define void @dummy() {
entry:
  ret void
}
