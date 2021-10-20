# SEEDLabs -- Buffer Overflow Attack Lab (Set-UID)

## Overview

*Buffer overflow* is the condition in which a program attempts to write data beyond the boundary of a buffer. This vulnerability can be exploited by a malicious user to alter the flow control of a program, leading to the execution of malicious code. 

In this lab, the objective is to gain practical insights into this type of vulnerability, and learn how to exploit the vulnerability in attacks. The following topics are covered here:

1. Buffer overflow vulnerability and attack
2. Stack layout
3. Address randomisation, non-execuatable stacks, and StackGuard
4. Shellcode (32- and 64-bit)

All code found below are available [here](./src).

## Environment setup

Modern operating systems have implemented several security mechanisms to make the buffer overflow attack difficult. To simplify our attacks, we need to disable them first. Later on, we will enable them and see if our attacks are still successful.

### Address space randomisation

Ubuntu and several other Linux-based systems use address space randomisation to randomise the starting addresses of the heap and stack. This makes guessing the exact addresses difficult -- guessing addresses is one of the critical steps of buffer overflow attacks. This feature can be disabled using the command:

```bash
~$ sudo sysctl -w kernel.randomize_va_space=0
```

### Configuring `/bin/sh`

In recent versions of Ubuntu OS, `/bin/sh` is a symbolic link pointing to the `/bin/dash` shell. `dash`, as well as `bash`, has implemention a security countermeasure that prevents itself from being executed in a `Set-UID` process. Basically, if they detect that they are being executed in a `Set-UID` process, they will immediately change the *effective user ID* to the *process's real user ID*, essentially dropping the privilege. 

Our target program here is a `Set-UID` program, and our attack relies on running `/bin/sh`. Thus, the countermeasure in `dash` makes our attack more difficult. Therefore, we will link `/bin/sh` to another shell that does not have such a countermeasure -- `zsh`. To do so, we use the command

```bash
~$ sudo ln -sf /bin/zsh /bin/sh
```

### StackGuard and non-executable stack

These are two additional countermeasures that are implemented in the system, and are turned off during compilation of the target program.

## Task 1: Getting familiar with shellcode