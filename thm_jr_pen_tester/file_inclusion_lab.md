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

## Lab #3

We are again given an input field, and we try to make a request to `/etc/passwd`. 

![File Inclusion lab 3 error](./img/file_inclusion_lab_3_error.png "File Inclusion lab 3 error")

From the error, we can see that:

1. the file path is taken to be relative to the `includes/` directory (similar to [Lab #2](#lab-2)), and
2. the file name is appended with `.php`. 

To overcome this, we use the null byte trick. We know this will work since the second error tells us that the system is running PHP 5.2. We pass the value `../../../../etc/passwd%00` to the `file` parameter.

![File Inclusion lab 3 passwd](./img/file_inclusion_lab_3_passwd.png "File Inclusion lab 3 passwd")

## Lab #4

We are again given an input field, and we perform the usual recon. 

![File Inclusion lab 4 function](./img/file_inclusion_lab_4_function.png "File Inclusion lab 4 function")

We see that the relevant function here is `file_get_contents()`.

![File Inclusion lab 4 blocked](./img/file_inclusion_lab_4_blocked.png "File Inclusion lab 4 blocked")

It seems like the application filters the string for `/etc/passwd`. To bypass this, we use the `/.` trick, and send the request for `/etc/passwd/.` instead.

![File Inclusion lab 4 blocked](./img/file_inclusion_lab_4_passwd.png "File Inclusion lab 4 passwd")

## Lab #5

Performing the usual recon shows us that the substring `../` is replaced by an empty string.

![File Inclusion lab 5 filtered](./img/file_inclusion_lab_5_filtered.png "File Inclusion lab 5 filtered")

Using the payload `....//....//....//....//etc/passwd` bypasses the filtering, and we can successfully read `/etc/passwd`.

![File Inclusion lab 5 passwd](./img/file_inclusion_lab_5_passwd.png "File Inclusion lab 5 passwd")

## Lab #6

Recon tells us that only files in the `THM-profile` directory can be accessed. 

![File Inclusion lab 6 blocked](./img/file_inclusion_lab_6_blocked.png "File Inclusion lab 6 blocked")

To bypass this, we include the required directory in the payload: `THM-profile/../../../../etc/os-release`, and we successfully read the file.

![File Inclusion lab 6 os-release](./img/file_inclusion_lab_6_osrelease.png "File Inclusion lab 6 os-release")


## Challenge

![Challenge page](./img/file_inclusion_chall.png "Challenge page")

**Challenge #1**

The page tells us that we need to send a `POST` request with the `file` parameter.

![Challenge 1 page](./img/file_inclusion_chall_1.png "Challenge 1 page")

We send a `POST` request, with the payload: `file=/etc/flag1` and it gives us the flag.

![Challenge 1 request](./img/file_inclusion_chall_1_post.png "Challenge 1 request")

![Challenge 1 flag](./img/file_inclusion_chall_1_flag.png "Challenge 1 flag")

>  F1x3d-iNpu7-f0rrn 

**Challenge 2**

The page tells us to refresh the page, but refreshing does not change anything.

![Challenge 2 page](./img/file_inclusion_chall_2.png "Challenge 2 page")

We open the developer tools and notice that there is a cookie:

![Challenge 2 cookie](./img/file_inclusion_chall_2_cookie.png "Challenge 2 cookie")

We try changing the value of the cookie to "Admin" and refresh the page.

![Challenge 2 "Admin" cookie](./img/file_inclusion_chall_2_admin.png "Challenge 2 \"Admin\" cookie")

We see that this causes the `include()` function to be `include(includes/Admin.php)`. Thus, the `include()` function on the web server should have the following structure:

```php
include("includes" . <value of THM cookie> . ".php")
```

The error messages also tell us that server is running PHP 5.2, so we can use the null byte trick, and that the application directory is `/var/www/html`. Thus, to get to `/etc/flag2`, we set the cookie value to `../../../../etc/flag2%00`.

![Challenge 2 flag](./img/file_inclusion_chall_2_flag.png "Challenge 2 flag")

> c00k13_i5_yuMmy1