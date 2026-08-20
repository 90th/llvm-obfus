.text
.p2align 4
selfchk_static_target:
  lea selfchk_static_data(%rip), %rax
  ret
  .fill 24, 1, 0x90

.data
selfchk_static_data:
  .quad 0

.section .obfsc.88,"a",@progbits
.p2align 3
selfchk_static_record:
  .long 0x4353424f
  .short 1
  .short 96
  .long 1
  .long 1
  .long 1
  .long 1
  .quad 88
  .quad selfchk_static_target - selfchk_static_record
  .long 1
  .long 0
  .long 16
  .long 0
  .quad 0x55
  .quad 0
  .zero 24
