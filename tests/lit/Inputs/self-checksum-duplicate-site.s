.text
.p2align 4
selfchk_duplicate_target:
  ret
  .fill 31, 1, 0x90

.section .obfsc.123,"a",@progbits
.p2align 3
selfchk_duplicate_record:
  .long 0x4353424f
  .short 1
  .short 96
  .long 1
  .long 1
  .long 1
  .long 1
  .quad 123
  .quad selfchk_duplicate_target - selfchk_duplicate_record
  .long 1
  .long 0
  .long 16
  .long 0
  .quad 0x55
  .quad 0
  .zero 24
