.text
.globl entry
entry:
  xorl %eax, %eax
  retq

.p2align 4
sibling:
  .quad anchor
  .quad anchor

.data
.p2align 3
anchor:
  .quad 0

.section .obfsc$M,"dr"
.p2align 3
record:
  .long 0x4353424f
  .short 1
  .short 96
  .long 1
  .long 1
  .long 2
  .long 1
  .quad 123
  .quad sibling - record
  .long 2
  .long 0
  .long 16
  .long 0
  .quad 0x12345678
  .quad 0
  .zero 24
