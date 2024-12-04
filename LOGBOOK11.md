# Seedlab Week #11 (Public Key Infrastructure - PKI)

# Part 1: SeedLab Tasks

### Initial Setup

Before starting this SeedLab, there is a simple initial setup consisting of the following steps:
- Launch the docker container for this seedlabs (which can be done with the `dcbuild` and `dcup` commands)
- Add the necessary entries in the /etc/hosts file, mapping the container's IP address

<p align="center" justify="center">
    <img src="./assets/LOGBOOK11/init_hosts.png">
</p>

In this case, we added these two entries. The first one is necessary in order to follow the example of the SeedLab. The second one corresponds to the custom name we will use throughout the rest of the tasks.

## Task 1: Becoming a Certificate Authority (CA)

For this task, we will create a root Certificate Authority (self-signed) and use it to issue certificates for others (in this case, our "randomwebsite").

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
echo "1000" > serial
```

We also need to uncomment the `unique_subject` line shown previously, to allow creation of certifications with the same subject.

After this OpenSSL setup, we are ready to become a CA. We can cd back into the `openssl.conf` directory and all we need to do is run the following command:
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

## Task 3: Generating a Certificate for your server

## Task 4: Deploying Certificate in an Apache-Based HTTPS Website

## Task 5: Launching a Man-In-The-Middle Attack

## Task 6: Launching a Man-In-The-Middle Attack with a Compromised CA

# Part 2: Compromised Certifica Authorities

<!-- 
TODO: 
    confirmar o tema na aula teórica:
- supostamente é Certificate Revocation List
- atacante pode tentar evitar o uso de CRLs
-->
