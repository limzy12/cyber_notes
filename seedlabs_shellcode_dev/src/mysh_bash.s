section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor  eax, eax 
      mov  al, "h"      ; Store the single character 'h' into eax
      push eax
      push "/bas"
      push "/bin"
      mov  ebx, esp     ; Get the string address

      ; Construct the argument array argv[]
      xor  eax, eax     ; Set eax to 0
      push eax          ; argv[1] = 0
      push ebx          ; argv[0] points "/bin//sh"
      mov  ecx, esp     ; Get the address of argv[]
   
      ; For environment variable 
      xor  edx, edx     ; No env variables 

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
