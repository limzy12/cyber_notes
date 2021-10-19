section .text
  global _start
    _start:
      ; Store "/bin/sh" on stack
      xor  eax, eax
      push eax          ; Use 0 to terminate the string
      push "//sh"
      push "/bin"
      mov  ebx, esp     ; Get the string address

      ; Store "-c" on stack
      mov   ax, "-c"    ; Store 16-bit "-c" into lower 16-bits of eax.
      push eax
      mov  ecx, esp     ; Store address of "-c"

      ; Store "ls -la" on stack
      xor  eax, eax     ; Clear eax
      mov   ax, "la"    ; Store 16-bit "la" into lower 16-bits of eax
      push eax
      push "ls -"
      mov  edx, esp     ; Store address of "ls -la"

      ; Construct the argument array argv[]
      xor  eax, eax     ; Clear eax
      push eax          ; argv[3] = 0
      push edx          ; argv[2] points "ls -la"
      push ecx          ; argv[1] points "-c"
      push ebx          ; argv[0] points "/bin//sh"
      mov  ecx, esp     ; Get the address of argv[]

      ; For environment variable
      xor  edx, edx     ; No env variables

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
