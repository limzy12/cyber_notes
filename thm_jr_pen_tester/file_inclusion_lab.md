# Solutions to File Inclusion lab

Below are solutions to the lab provided in the [File Inclusion room](./1b_intro_to_web_hacking.md#file_inclusion).

![File Inclusion lab home](./img/file_inclusion_lab_home.png "File Inclusion lab home")

## Lab #1

We are given an input field, where we can specify a file name to be included.

![File Inclusion lab 1](./img/file_inclusion_lab_1.png "File Inclusion lab 1")

We observe what happens when `welcome.php` is submitted in the form.

![File Inclusion lab 1 test](./img/file_inclusion_lab_1_test.png "File Inclusion lab 1 test")

Notice that the file name is passed as a `GET` parameter, `file`. If we want to access and read, say `/etc/passwd`, we can request for `lab1.php?file=/etc/passwd`. 

![File Inclusion lab 1 passwd](./img/file_inclusion_lab_1_passwd.png "File Inclusion lab 1 passwd")

## Lab #2

We are given an input field, similar to Lab #1. 

![File Inclusion lab 2](./img/file_inclusion_lab_2.png "File Inclusion lab 2")

We attempt to directly request for `/etc/passwd`, but we get an error. From the error, it seems that the `include()` function is trying to include a file at the path `includes//etc/passwd`, which does not exist.

![File Inclusion lab 2 passwd error](./img/file_inclusion_lab_2_passwd_error.png "File Inclusion lab 2 passwd error")

Thus, we know that the file path that we pass into the `file` parameter will be taken **relative** to the directory `includes/`. To get to `/etc/passwd`, we use `../` to traverse the path, and pass the value `../../../../etc/passwd` to the `file` parameter.

![File Inclusion lab 2 passwd](./img/file_inclusion_lab_2_passwd.png "File Inclusion lab 2 passwd")