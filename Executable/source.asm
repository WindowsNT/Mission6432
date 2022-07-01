format MS64 COFF



public myf1 as 'myf1'

section '.code' code readable writable executable

WhatToPass:
dd 0

WhatToCall:
dd 0

Back32:
USE32
; Call function, takes 1 parameter
push eax
push dword [WhatToPass]
mov eax, [WhatToCall]
call eax
pop eax

; jump back to x64
USE64
db 0eah
ret_64:
dd 0
dw 0x33
nop

myf1:

cmp ecx,0
jnz .okx
ret

.okx:
mov dword [WhatToCall],ecx
mov dword [WhatToPass],edx
mov dword  [ret_64],j2
push 0x23    
xor rcx,rcx    
mov ecx,Back32  
push rcx
retf


j2:

ret
