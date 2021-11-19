# 1a. Introduction to Web Hacking

Understanding and exploiting common web application vulnerabilities. In this part, we look at various web vulnerabilities and how to exploit them. 

## Insecure Direct Object Reference (IDOR)

*IDOR* is a type of access control vulnerability. It occurs when a webserver receives user-supplied input to retrieve objects (files, data, documents, etc.) and the input data is **not validated** on the server-side to confirm that the requested object belongs to the user requesting it. 

### IDOR example

Suppose we have registered ourself on some web service, and our private profile on this service exists at `/profile?id=1305`. However, we can attempt to change the query string to `id=1000`. If we are now able to see another user's private information, then we have discovered an IDOR vulnerability. 

### IDORs in encoded IDs

When passing data from webpage to webpage, either by `POST` or `GET` or cookies, developers will often encode the raw data. This ensures that the web server will understand the contents of the data.

The most commonly used encoding is base64 which uses the characters a-z, A-Z, 0-9, + and /. To determine if an IDOR vulnerability is present, we first decode the data into its raw form, tamper with it, then re-encode it before sending it back to the server and observing the response.

![IDOR encoded data](./img/IDOR_encoded.png "IDOR encoded data")

### IDORs in hashed IDs

Hashed data are more complicated to deal with due to the irreversibility of the hashing process. Nonetheless, it is worthwhile to use databases like [Crackstation](https://crackstation.net/) to see if a matching string can be found. 

If we are able to identify the unhashed data, we can use a similar process as encoded data to test for IDOR.

### IDORs in unpredictable IDs

If we are unable to determine the data used to request the objects, we can attempt to create two accounts and swap the ID numbers between them. If we can use one account to view the content of the other account by using their ID, then we have found an IDOR vulnerability.

### Where IDORs are located

The vulnerable endpoint may not always be a query string in the URL. It can also be content the browser loads via an AJAX request or something referenced in a Javascript file.

Sometimes endpoints may contain an unreferences parameter that was used during development, but accidentally got pushed to production. 

