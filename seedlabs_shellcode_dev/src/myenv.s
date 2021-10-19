section .text
  global _start
    _start:
      ; Store the argument string on stack
      xor  eax, eax
      push eax          ; Use 0 to terminate the string
      push "/env"
      push "/bin"
      push "/usr"
      mov  ebx, esp     ; Get the string address

      ; Construct the argument array argv[]
      push eax          ; argv[1] = 0
      push ebx          ; argv[0] points "/usr/bin/env"
      mov  ecx, esp     ; Get the address of argv[]

      ; Construct env strings on stack
      push eax          ; 0 to terminate string
      push "1234"       ;
      push "aaa="       ; "aaa=1234"
      push eax          ; 0 to terminate string
      push "5678"       ;
      push "bbb="       ; "bbb=5678"
      mov  al, "4"      ;
      push eax          ;
      push "=123"       ;
      push "cccc"       ; "cccc=1234"
      mov  eax, esp     ;

      ; Pushing env variable array onto stack
      xor  edx, edx     ;
      push edx		; 0 to terminate array
      push eax		;
      add  eax, 0xc     ; 0xc = 12
      push eax          ;
      add  eax, 0xc     ;
      push eax          ;
      mov  edx, esp     ;

      ; Invoke execve()
      xor  eax, eax     ; eax = 0x00000000
      mov   al, 0x0b    ; eax = 0x0000000b
      int 0x80
