; REQUIRES: system-windows-x86-64
;
; O0/O2 x vm/strong_vm consumers read caller-owned copies from two independent
; Windows x64 DLL producers. IDs 1..3 cover file-local, C++ local-static, and
; empty arrays. Lazy and normal shared-CRT constructor strategies authenticate
; before every successful copy, including first application copies after CRT
; decoding and repeated/warm calls. Selected vm/strong_vm exporters use ctor.
; Independent raw controls check exact bytes, NUL-inclusive capacities, all
; statuses, consumer effects, wrong-owner rejection, and a V2-only DLL.
; PE section/export parsing finds private V3 descriptors without exported hooks
; or PDBs, follows bounded producer data pointers, and proves independent keys.
; Data-only cache/tag/ciphertext/length/version corruption runs in native child
; processes. A shared destination/effect witness proves unchanged bytes and
; five ordinary query/error returns before the real C000001D runtime trap.
; GetModuleHandleExW uses UNCHANGED_REFCOUNT, never PIN. FreeLibrary must remove
; each producer (GetModuleHandleW==NULL) before saved copies are consumed again.
; Exact EAT/name tables forbid hidden helpers, data, ordinal-only or .def leaks.
; Native link negatives cover runtime exports/aliases/NONAME, static/foreign-data
; ownership, and raw protected-manifest claims. Raw links with the matching
; configured runtime prove each requested export is resolvable. Default negatives
; include LLD, nonincremental MSVC, and /DEBUG /INCREMENTAL /OPT:NOREF /OPT:NOICF
; MSVC. Raw alias/NONAME EAT RVAs follow actual bounded executable E9 chains to
; the V3 MAP body; legitimate public accessor ILT thunks must stay accepted.
; No app copy executes in DllMain or CRT$XL callbacks. TEMP retains all evidence.
; RUN: %python %S/../Inputs/cross_dll_string_copy.py --wrapper %obf_clangxx --clang %raw_clang
;
define void @dummy() {
entry:
  ret void
}
