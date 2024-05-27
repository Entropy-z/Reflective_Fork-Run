section .text

global EggHunter

EggHunter:
    mov r8, 0xB0C0ACDC
dec:
    dec rcx
    cmp r8d, [ rcx ]
    jne dec
    mov rax, rcx
    sub rax, 0x4
    cmp r8d, [ rax ]
    jne dec
    sub rax, 0x50
    ret