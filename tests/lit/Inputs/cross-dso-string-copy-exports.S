/* The harness selects one public export per isolated link. */
#ifndef COPY_EXPORT_CASE
#error COPY_EXPORT_CASE is required
#endif
#ifndef EXPORT_NAME
#error EXPORT_NAME is required
#endif

#if COPY_EXPORT_CASE == 6 || COPY_EXPORT_CASE == 12
.data
.globl EXPORT_NAME
.type EXPORT_NAME,@object
EXPORT_NAME:
#if COPY_EXPORT_CASE == 12
  .quad EXPORT_TARGET
#else
  .quad 0
#endif
.size EXPORT_NAME, .-EXPORT_NAME
#else
#if COPY_EXPORT_CASE == 10
.section .copy_truncated_edge,"ax",@progbits
#else
.text
#endif
.globl EXPORT_NAME
.type EXPORT_NAME,@function
EXPORT_NAME:
#if COPY_EXPORT_CASE == 2
  ret
#elif COPY_EXPORT_CASE == 3 || COPY_EXPORT_CASE == 11
  .byte 0xe9
  .long EXPORT_TARGET - . - 4
#elif COPY_EXPORT_CASE == 4
  .byte 0xeb
  .byte .Lbridge - . - 1
.Lbridge:
  .byte 0xe9
  .long EXPORT_TARGET - . - 4
#elif COPY_EXPORT_CASE == 5
  .byte 0xe9
  .long .Lmiddle - . - 4
.Lmiddle:
  .byte 0xeb
  .byte .Lbridge - . - 1
.Lbridge:
  .byte 0xe9
  .long EXPORT_TARGET - . - 4
#elif COPY_EXPORT_CASE == 7
  .byte 0xe9
  .long -5
#elif COPY_EXPORT_CASE == 8
  .byte 0xe9
  .long 0x7fffffff
#elif COPY_EXPORT_CASE == 9
  .byte 0xe9
  .long .Ldata - . - 4
#elif COPY_EXPORT_CASE == 10
  .byte 0xe9
#elif COPY_EXPORT_CASE == 13
  .byte 0xeb
  .byte .Lforward - . - 1
.Lbackward:
  .byte 0xe9
  .long EXPORT_TARGET - . - 4
.Lforward:
  .byte 0xeb
  .byte .Lbackward - . - 1
#elif COPY_EXPORT_CASE == 14
  .rept COPY_THUNK_HOPS - 1
  .byte 0xe9
  .long 0
  .endr
  .byte 0xe9
  .long EXPORT_TARGET - . - 4
#else
#error unsupported COPY_EXPORT_CASE
#endif
.size EXPORT_NAME, .-EXPORT_NAME
#endif

#if COPY_EXPORT_CASE == 9
.data
.Ldata:
  .quad 0
#endif
.section .note.GNU-stack,"",@progbits
