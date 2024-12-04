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
This request will be correctly authenticated and we will see the server will respond with the following message:

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
```
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
