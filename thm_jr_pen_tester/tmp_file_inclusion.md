<!--- To be added into 1b --->

## File Inclusion

Web applications can be written to request access to files (images, text, etc.) on a system via `GET` parameters. For example, if a user wants to access a CV on a web application, the request may look something like `http://webapp.thm/get.php?file=userCV.pdf`.

In such cases, file inclusion vulnerabilities occur when the user input is not sanitised or validated, and the user has full control over the input. 

If an attacker is able to exploit file inclusion vulnerabilities, they will be able to leak sensitive data. Furthermore, if an attacker is able to write to the server, it may be possible for them to gain remote code execution (RCE).

