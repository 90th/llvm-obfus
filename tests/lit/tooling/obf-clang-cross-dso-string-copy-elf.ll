; REQUIRES: system-linux-x86-64, system-glibc, has-lld-llvm-match
;
; O0/O2 x vm/strong_vm consumers read caller-owned copies from two independent
; native producers. Raw controls check exact strings, capacities, statuses, and
; effects. The host unloads each producer and proves actual mapping removal
; before it consumes saved copies. A v2-only producer must not resolve v1.
; IDs 1..3 cover file-local, C++ function-local static, and empty arrays.
; Lazy and constructor-backed vm/strong_vm producers authenticate each copy.
; Lazy rows disable constructor fallback and retain cold state, including empty
; sources, through queries and errors. Data-only corruption checks cold and warm
; copies, except lazy cache corruption needs a successful first copy.
; Queries and errors return ordinary statuses without certifying corrupt data.
; The next successful copy must trap without changing destinations or effects.
; Narrow rejection cases keep strict static ownership and raw-manifest rules.
; LLD and GNU BFD raw controls use the same protected object and runtime as the
; managed link. Actual .dynsym and MAP addresses prove private runtime aliases,
; data aliases, stripped aliases, and bounded E9/EB routes. Private helper and
; payload exports must fail in the real linker before native validation.
; Legitimate producers export exchange_copy_v1 and no rt_core_* symbols.
; Fresh-process pthread barriers start same-source calls for IDs 1..3, independent
; sources, and two independent producers. Private bundle offsets prove lazy cold
; states and zero caches before release, including the empty source. Concurrent
; copies mix exact successes, queries, short capacities, and invalid arguments;
; TLS counters avoid shared observation races. Warm copies use independently
; selected vm/strong_vm producer and consumer policies at O0/O2 and lazy/ctor.
; Host admission closes with admitted work parked in host code, rejects new
; admissions without module calls, drains and joins, and clears producer callables
; before actual unload. Every saved worker and owner copy is consumed afterward.
; A start barrier does not prove deterministic decoder overlap or loader-lock
; contention. --only-concurrency runs these cases without unrelated negatives.
; All compiler ledgers, commands, native outcomes, and scratch stay under /var/tmp.
; RUN: %python %S/../Inputs/cross_dso_string_copy.py --wrapper %obf_clang --clang %raw_clang --runtime %obf_runtime
;
define void @dummy() {
entry:
  ret void
}
