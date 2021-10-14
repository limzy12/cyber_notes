section .text
  global _start
    _start:
      ; Comparing between moving an 8-bit value to eax vs. al
      mov  eax, 0x99	; moving 0x99 into eax
      mov   al, 0x99	; moving 0x99 into al
