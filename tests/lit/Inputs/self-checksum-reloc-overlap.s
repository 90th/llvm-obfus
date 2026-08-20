.text
.globl _start
_start:
  xor %edi, %edi
  mov $60, %eax
  syscall

.p2align 4
selfchk_target:
  .quad selfchk_target
  .quad selfchk_target
  .fill 16, 1, 0x90

.section .obfsc.99,"a",@progbits
.p2align 3
selfchk_record:
  .long 0x4353424f
  .short 1
  .short 96
  .long 1
  .long 1
  .long 1
  .long 1
  .quad 99
  .quad selfchk_target - selfchk_record
  .long 1
  .long 0
  .long 16
  .long 0
  .quad 0x55
  .quad 0
  .zero 24
