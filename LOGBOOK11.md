# Seedlab Week #11 (Public Key Infrastructure - PKI)

# Part 1: Seedlab Tasks

### Initial Setup

Before starting this seedlab, there is a simple initial setup consisting of the following steps:
- Launch the docker container for this seedlabs (which can be done with the `dcbuild` and `dcup` commands)
- Add the necessary entries in the `/etc/hosts` file, mapping the container's IP address

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/init_hosts.png">
</p>

In this case, we added these two entries. The first one is necessary in order to follow the example of the seedlab. The second one corresponds to the custom name we will use throughout the rest of the tasks.

## Task 1: Becoming a Certificate Authority (CA)

For this task, we will create a root Certificate Authority (self-signed) and use it to issue certificates for others (in this case, `www.silva2024.com`).

To become a root Certificate Authority, we will use OpenSSL with a different configurations. The default configuration file is located in `/usr/lib/ssl/openssl.cnf`. The first thing to do is to copy this configuration to a new directory (this way we can change it without consequences, and use it for the rest of the commands):
```sh
cp /usr/lib/ssl/openssl.cnf .
```

After obtaining this configuration file, we will change it and create some necessary directories and files, based on the `[ CA_default ]` section of the file. The section of the file is the following:

```
[ CA_default ]
dir             =   ./demoCA        # Where everything is kept
certs           =   $dir/certs      # Where the issued certs are kept
crl_dir         =   $dir/crl        # Where the issued crl are kept
database        =   $dir/index.txt  # database index file.
unique_subject  =   no              # Set to ’no’ to allow creation of
                                    # several certs with same subject.
new_certs_dir   =   $dir/newcerts   # default place for new certs.
serial          =   $dir/serial     # The current serial number
```
And to create the initial setup we need to execute the following commands (starting from the same directory as the configuration file):
```sh
mkdir ./demoCA
cd demoCA
mkdir certs
mkdir crl
mkdir newcerts
touch index.txt
echo "42" > serial
```

We also need to uncomment the `unique_subject` line shown previously, to allow creation of certifications with the same subject.

After this OpenSSL setup, we are ready to become a CA. We can cd back into the `openssl.cnf` directory and all we need to do is run the following command:
```sh
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
-keyout ca.key -out ca.crt \
-subj "/CN=www.modelCA.com/O=Model CA LTD./C=US" \
-passout pass:dees
```
This command should create two files:
- `ca.key` which contains the information needed to create pairs of public and private keys. This file can be analyzed with `openssl rsa -in ca.key -text -noout`.
- `ca.crt`, the certificate that associates the public key to the modelCA entity. This file can be analyzed with `openssl x509 -in ca.crt -text -noout`.

### Questions:

#### What part of the certificate indicates this is a CA’s certificate?

By analyzing the contents of the `ca.crt` file, we can see that this certificate is a CA's certificate because it contains the value `CA:TRUE` in the `X509v3 extensions`.

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task1_ca.png">
</p>

#### What part of the certificate indicates this is a self-signed certificate?

Once agian, By analyzing the contents of the `ca.crt` file, we can see that this certificate is self-signed not only because the `Issuer` and `Subject` are the same, but also since the `Subject Key Identifier` is the same as the `Authority Key Identifier`.

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task1_ss.png">
    <img src="./assets/LOGBOOK11/task1_ca.png">
</p>

#### In the RSA algorithm, we have a public exponent e, a private exponent d, a modulus n, and two secret numbers p and q, such that n = pq. Please identify the values for these elements in your certificate and key files.

| Field                | Key `ca.key`      | Certificate `ca.crt` |
| -------------------- | ----------------- | -------------------- |
| Public Exponent (e)  | `publicExponent`  | `Exponent`           |
| Private Exponent (d) | `privateExponent` |                      |
| Modulus (n)          | `modulus`         | `Modulus`            |
| p                    | `prime1`          |                      |
| q                    | `prime2`          |                      |

Screenshots of these values from the file output are also shown below:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task1_valcrt.png">
    Values shown in the `ca.crt` file
</p>

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task1_valmod.png">
    <img src="./assets/LOGBOOK11/task1_valexp.png">
    <img src="./assets/LOGBOOK11/task1_valprm.png">
    Values shown in the `ca.key` file
</p>

## Task 2: Generating a Certificate Request for Your Web Server

After becoming a Certificate Authority (CA), we will use this to create a public key certificate for our own webserver (www.silva2024.com). 

The first step is to generate the Certificate Signing Request (CSR), which can be done with the following command:
```bash
openssl req -newkey rsa:2048 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=www.silva2024.com/O=Silva 2024 Inc./C=US" \
    -passout pass:dees
```
This command should create two files:
- `server.key` file (with a similar structure and purpose as the `ca.key`). This file can be analyzed with `openssl rsa -in server.key -text -noout`.
- `server.csr` (the certificate signing request with the public key). This file can be analyzed with `openssl req -in server.csr -text -noout`.
  
As solicited by the guide, we should also add two alternative names to the CSR, for this, we can run a command similar to the previous one:
```bash
openssl req -newkey rsa:2048 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=www.silva2024.com/O=silva2024 Inc./C=US" \
    -passout pass:dees
    -addext "subjectAltName = DNS:www.silva2024.com, \
                              DNS:www.silva20241.com, \
                              DNS:www.silva20242.com"
```
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task2_altnames.png">
</p>

## Task 3: Generating a Certificate for your server

After generating a Certificate Signing Request, the Certificate Authority needs to sign it to form the Certificate that can be used by the other entity. In this lab, we will do this process ourselves and generate `server.crt` using `server.csr`, `ca.key` and `ca.crt`.

But first, we need to uncomment the `copy_extensions` line in the `openssl.cnf`:
```
# Extension copying option: use with caution.
copy_extensions = copy
```

Finally, we can generate the certificate for `www.silva2024.com` with the following command:
```bash
openssl ca -config myCA_openssl.cnf -policy policy_anything \
    -md sha256 -days 3650 \
    -in server.csr -out server.crt -batch \
    -cert ca.crt -keyfile ca.key
```
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task3_cert.png">
</p>

## Task 4: Deploying Certificate in an Apache-Based HTTPS Website

Now that we have create a Certificate from our Certificate Authority for our web server (`www.silva2024.com`), we can deploy our HTTPS website with it, using Apache. The guide for this lab already create an instance for the `bank32` example, but it also explains how the process to replicate the same using a different website.

The first step is to obtain shell access to the container, which can be done using the `docksh` alias.  
After that, we can go to the `/etc/apache2/sites-available` and create a configuration for our website, similar to the one in the `bank32_apache_ssl.conf`.
The final configuration for our website is shown below:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task4_apache.png">
</p>

We named this configuration `silva2024.conf`. Please note the changes to `ServerName`, `SSLCertificateFile` and `SSLCertificateKeyFile`. We kept the `DocumentRoot` the same as the example (screenshots shown below).

After creating the Apache configuration, we need to add the adequate certificate and key to the `certs` directory, which can be done using the following commands (from outside the container):
```sh
docker cp server.key <CONTAINER-ID>:/certs/silva2024.key
docker cp server.crt <CONTAINER-ID>:/certs/silva2024.crt
```

Finally, we can launch our web server with:
```sh
a2enmod ssl            # Enable the SSL module
a2ensite silva2024     # Enable the site described in the file
service apache2 start  # Start the server
```

When acessing `http://www.silva2024.com` we will get the following screen which shows that the web server is now running as intended.
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task4_http.png">
</p>

However, the setup we made should allow us to access the webserver through `https://www.silva2024.com`.
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task4_risk.png">
</p>

However, when we access the server, we see a `potential security risk ahead` message. This is because, although the web server has certificate, the Certificate Authority is not recognized by the browser. 

To fix this, we just need to go to `about:preferences#privacy` > `View Certificates` > `Import` and select our `ca.crt` file. We should then see a new entry on the Certificate Manager for ModelCA.
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task4_cert.png">
    <img src="./assets/LOGBOOK11/task4_cert2.png">
</p>

Now, when we access the `https://www.silva2024.com`, we will be greeted with the green `Hello World` message.

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task4_https.png">
</p>

## Task 5: Launching a Man-In-The-Middle Attack

Now that we have set up a CA and a web server using a certificate from that CA, we will explore Man-in-the-Middle (MITM) attacks and how Public Key Infrastructures defend against them.

To simulate our attack, we will start by setting up an Apache server (similar to the one in task 4) for a fake website (simulating a malicious website). For this one, we decided to use `www.moodle.pt` and the configuration file `moodle.conf` is as follows:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task5_apache.png">
</p>

After this, we should also run the following commands to start the web server in the container:
Finally, we can launch our web server with:
```sh
a2enmod ssl              # Enable the SSL module
a2ensite moodle          # Enable the site described in the file
service apache2 restart  # Restart the server
```

After starting the web server, we should also add another line into our `/etc/hosts` file, for the new website:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task5_hosts.png">
</p>

Now that the new web server is ready, we can try to access it through `https://www.moodle.pt`. This time, the browser will also issue the `Warning: Potential Security Risk Ahead` since the CA has not signed the Certificate Signing Request for the fake website.
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task5_risk.png">
</p>

## Task 6: Launching a Man-In-The-Middle Attack with a Compromised CA

For this final task, the goal is to show how a compromised Certificate Authority can be exploited by an attacker to perform a Man-in-the-Middle attack.  
For this, we will continue with the `www.moodle.pt` example and assume that the private key of our Certificate Authority has been compromised.

If the private key has been compromised, an attacker can generate new Certificate Signing Requests and Certificates for different web servers. Therefore, the first part of the task is to replicate Tasks 2 and 3 with the fake website:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task6_csr.png">
    <img src="./assets/LOGBOOK11/task6_cert.png">
</p>

After creating the certificate and the key, we can send them to the container using commands similar to the previous ones:
```sh
docker cp server.key <CONTAINER-ID>:/certs/moodle.key
docker cp server.crt <CONTAINER-ID>:/certs/moodle.crt
```
And then we just need to update the configuration of the Apache server to use the newly created files:
<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task6_conf.png">
</p>

By restarting the Apache server, our new web server configuration for the fake website `www.moodle.pt` is now ready. Since we already have the Certificate Authority in our browser, we can now access the website using `https://www.moodle.pt`.

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/task6_https.png">
</p>

This is an example of how a compromised Certificate Authority can lead to Man-in-the-Middle attacks.

# Part 2: Compromised Certificate Authorities

There are a few mechanisms that can be used when a Certificate Authority (CA) is compromised. One of the main ones which we discussed in the theoretical classes is the **Certificate Revocation Lists** (CRLs).  
A CRL is a list periodically published by a CA that has certificates that have been compromised and therefore can no longer be trusted, so they should be avoided by browsers. When a CA is compromised, all of their issued certificates can be added to the CRL.  
In practice this solution can be challenging and the attacker can try some workarounds such as:
 - Intercept or block network traffic associated with the CRL, preventing clients from downloading the updated CRL and verifying if the CA has been compromised or not.
 - Use outdated CRLs that don't have information about recently compromised CAs, therefore letting the browser trust certificates that have already been revoked.
 - Exploit certificates with short validity durations, which makes it impractical to revoke them in CRLs before they expire naturally.