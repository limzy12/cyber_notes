section .text
  global _start
    _start:
	BITS 32
	jmp short two
    one:
 	pop ebx
 	xor eax, eax
 	mov [ebx+0xc] , eax
        mov [ebx+0x10], ebx
        lea ecx, [ebx+0x10]
        mov [ebx+0x14], eax
        mov [ebx+0x1d], al
        mov [ebx+0x23], al
        lea eax, [ebx+0x18]
        mov [ebx+0x24], eax
        lea eax, [ebx+0x1e]
        mov [ebx+0x28], eax
        lea edx, [ebx+0x24]
        xor eax, eax
        mov [ebx+0x2c], eax
 	mov al,  0x0b
 	int 0x80
     two:
 	call one
 	db '/usr/bin/env****argv****aa=11*bb=22*env1env2****'
