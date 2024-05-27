section .text

global Setup

Setup         
    push rsi
    mov  rsi, rsp
    and  rsp, 0x0FFFFFFFFFFFFFFF0
    sub  rsp, 0x20
    call ReflectiveLdr
    mov  rsp, rsi
    pop  rsi
    pop  rcx
    add  rsp, 0x20
    and  rsp, 0x0FFFFFFFFFFFFFFF0
    jmp  rcx 
