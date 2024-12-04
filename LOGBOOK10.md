# Seedlab Week #10 (Hash Length Extension)

# Task 1: Send Request to List Files

For this first task, the goal is to explore how to send requests to the server and analyze how the server responds to the different requests. To do this, we will create a custom request to list and "download" files from the server.

The structure of the list request is the following: `http://www.seedlab-hashlen.com/?myname=<name>&uid=<need-to-fill>&lstcmd=1&mac=<need-to-calculate>`, where: 
- `myname` is the first and last name of one of the elements of the group (in this case, we used ``)<!-- TODO: insert name here -->
- `uid` is one of the uid obtained from the file `key.txt` (possible values are shown below)
- `lstcmd=1` specifies that the request aims to list the files from the server
- `mac` is calculated using a SHA256 hash on the concatenation of the key (obtained from the `key.txt` file) with the argument part of the request

The contents of the `key.txt` file are the following:
```
1001:123456
1002:983abe
1004:98zjxc
1005:xciujk
```
In this file, the first column represents the UID and the second the key associated with each UID. In our case, we chose UID `` with the key `` <!-- TODO: Fill these values-->

After selecting the name and UID, we know that the argument part of the request will be: `myname=<name>&uid=<need-to-fill>&lstcmd=1`

So, we can already calculate the MAC. The message to hash will be `<key>:myname=<name>&uid=<need-to-fill>&lstcmd=1`, and the result is shown below:

```sh
$ echo -n "<key>:myname=<name>&uid=<need-to-fill>&lstcmd=1" | sha256sum
<!-- TODO: insert the final hash>
```

To send the request, we just have to place the MAC obtained in the correct field:
```
http://www.seedlab-hashlen.com/?myname=<name>&uid=<uid>&lstcmd=1&mac=<insert-mac>
```
This request will be correctly authenticated and we will see the server respond with the following message:

<!-- TODO: insert screenshot -->

In order to send the download request to the server, we need to execute the same steps as we did before, but, with an extra parameter in the argument as shown below:
```
http://www.seedlab-hashlen.com/?myname=<name>&uid=<uid>&lstcmd=1&download=secret.txt&mac=<mac>
```

After the lstcmd, we add the `&download=secret.txt` which will print the contents of the secret.txt file. Choosing the name, UID and key works exactly the same, but calculating the MAC will lead to a slightly different result, as we will have more parameters:
```sh
$ echo -n "<key>:myname=<name>&uid=<need-to-fill>&lstcmd=1&download=secret.txt" | sha256sum
<!-- TODO: insert the final hash>
```

The final request is constructed exactly the same as the previous one:
```\x
http://www.seedlab-hashlen.com/?myname=<name>&uid=<uid>&lstcmd=1&mac=<insert-mac>
```
This request will be correctly authenticated and we will see the server will respond with the following message:

<!-- TODO: insert screenshot -->

# Task 2: Create Padding

In this second task, we need to calculate the padding for the message request that lists the contents of the server.

According to the RFC6234, the padding of a SHA256 of a message of length L is:
  - one `\x80` byte
  - many `\x00` bytes to pad the contents until the next multiple of 64
  - the last 4 bytes correspond to the **length field** (number of bits in the message M = L * 8)

To help us in this task, we can use the Python interpreter for some quick calculations:
1. The first step is to obtain the length of the message we will be using (`<key>:myname=<name>&uid=<need-to-fill>&lstcmd=1`) which is <!-- insert value-->
2. The total length of the padding should then be 64 - xx = yy bytes
3. We can fill the entire length of the message with `\x00`, and then change the first byte to `\x80`
4. Since the message has a length L, it needs L * 8 = zz bits. This value corresponds to ww in hexadecimal, so the last values of the padding should be `\x00\x00\xww\xww`

Putting it all together, we end up with the follwing padding:
```
\x80\x00\x00...\xww\xww
```
Since we will need to add it to the server request, we can already write using `%` instead of `\x` as follows:
```
%80%00%00...%ww%ww
```

# Task 3: Length Extension Attack

For this final task, we will use the Length Extension Attack to send a request to download the contents of the file `secret.txt` without using the keys from the first task.

To do this, we will use the base request to list the contents of the file, for which we already know the valid MAC, as well as the padding calculated on the previous task.

The new request will use the following structure:
```
http://www.seedlab-hashlen.com/?myname=<name>&uid=<uid>&lstcmd=1<padding>&download=secret.txt&mac=<new-mac>
```

In order to obtain the new MAC, we will use the following code:

```C
/* length_ext.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

int main(int argc, const char *argv[]) {
    int i;
    unsigned char buffer[SHA256_DIGEST_LENGTH];
    SHA256_CTX c;

    SHA256_Init(&c);

    // Process initial message (64 bytes of '*')
    for (i = 0; i < 64; i++) {
        SHA256_Update(&c, "*", 1);
    }

    // Set MAC of the original padded message (manual initialization)
    c.h[0] = htole32(0x<fill with MAC>);
    c.h[1] = htole32(0x<fill with MAC>);
    c.h[2] = htole32(0x<fill with MAC>);
    c.h[3] = htole32(0x<fill with MAC>);
    c.h[4] = htole32(0x<fill with MAC>);
    c.h[5] = htole32(0x<fill with MAC>);
    c.h[6] = htole32(0x<fill with MAC>);
    c.h[7] = htole32(0x<fill with MAC>);

    // Append additional message
    SHA256_Update(&c, "&download=secret.txt", 20);

    // Finalize the SHA-256 hash
    SHA256_Final(buffer, &c);

    // Print the resulting hash
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    return 0;
}
```

To complete the request, we just have to fill the parameters:
```
http://www.seedlab-hashlen.com/?myname=<name>&uid=<uid>&lstcmd=1<padding>&download=secret.txt&mac=<new-mac>
```

By sending this request, the server will validate the request and we will see the contents as if we had executed a normal download request.

<!-- TODO: insert screenshot -->