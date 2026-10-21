.text
.global _start
_start:
    mov $60, %eax
    xor %edi, %edi
    syscall
.section .note.GNU-stack,"",@progbits
