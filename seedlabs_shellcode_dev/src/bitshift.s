section .text
  global _start
    _start:
      ; Using bitshift to insert values less than 32-bits
      mov  ebx, "xyz" ;  inserting a 24-bit value

      mov  ebx, "xyz#";  inserting the self-padded 24-bit value
      shl  ebx, 8     ;  shift left 8-bits
      shr  ebx, 8     ;  shift right 8-bits
