section .text

global RDIcaller

RDIcaller:
       call pop
       pop:
       pop rcx                  
   loop:
       xor rbx, rbx
       mov ebx, 0x5A4D
       dec rcx
       cmp bx,  [ rcx ]
       jne loop
       xor rax, rax
       mov ax,  [ rcx + 0x3C ]
       add rax, rcx
       xor rbx, rbx
       add bx,  0x4550
       cmp bx,  [ rax ]
       jne loop
       mov rax, rcx
   ret
