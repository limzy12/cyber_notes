section .text
  global _start
    _start:
      ; Comparing between mov and xor for setting register to zero
      mov  eax, 0    ; using mov to set to zero
      xor  eax, eax  ; using xor to set to zero
