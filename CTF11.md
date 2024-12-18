# CTF Week #11 (Weak Encryption)

In this CTF, we were given a ciphertext that was encrypted using AES in CTR mode. Our goal is to recover the secret key and decrypt the message to obtain the flag.

## Task 1

We were provided the ciphered message, which includes the nonce used in the cipher in hexadecimal and the ciphered text, also in hexadecimal:

```
32a200753d268cfb340c286516834711
7bf519da99a325f6d78521939a6d08ca6d4d3969128d
```

We were also provided with a `cipherspec.py` that implements AES-CTR encryption and decryption, used to encrypt the given message:

```py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

KEYLEN = 16

def gen():
	offset = 3 # Hotfix to make Crypto blazing fast!!
	key = bytearray(b'\x00'*(KEYLEN-offset))
	key.extend(os.urandom(offset))
	return bytes(key)

def enc(k, m, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	encryptor = cipher.encryptor()
	cph = b""
	cph += encryptor.update(m)
	cph += encryptor.finalize()
	return cph

def dec(k, c, nonce):
	cipher = Cipher(algorithms.AES(k), modes.CTR(nonce))
	decryptor = cipher.decryptor()
	msg = b""
	msg += decryptor.update(c)
	msg += decryptor.finalize()
	return msg
```

From the script, we can observe the functions:
- `gen()`: The key generation function, which produces a 16-byte key in which the first 13 bytes are always zero (0x00) and only the last 3 bytes are randomly generated.
- `enc()` and `dec()`: Straightforward AES-CTR implementations. Given a key, nonce, and message, `enc()` produces the ciphertext, and `dec()` recovers the original message from the ciphertext.

### Q&A

> **Q1: How can I use this ciphersuite to cipher and decipher data?**

**Answer:**

This code is designed to be used as follows:

```py
nonce = os.urandom(KEYLEN)
key = gen()
flag = b"my secret message"
cipher = enc(key, flag, nonce)
decrypted_flag = dec(key, cipher, nonce)
```

> **Q2: How can I use the vulnerability that I observed to break the code?**

**Answer:**

Since we know that the first 13 bytes of the key are zero and only the last 3 are random, this reduces the keyspace from 2^128 to 256^3 = 16,777,216 possible keys, so we can brute force all 256^3 combinations.

> **Q3: How can I automate this process, so that my attack knows that it found the flag?**

**Answer:**

We can write a simple loop that tries every candidate key, decrypts the ciphertext, and checks if the plaintext starts with `flag{`. Once found, we print the key and plaintext.

```py
import binascii
# pip install tqdm
from tqdm import tqdm

nonce = binascii.unhexlify('32a200753d268cfb340c286516834711')
ciphertext = binascii.unhexlify('7bf519da99a325f6d78521939a6d08ca6d4d3969128d')

for i in tqdm(range(256**3)):

	key = (b'\x00' * 13) + i.to_bytes(3, 'big')

	plaintext = dec(key, ciphertext, nonce)

	if b'flag{' == plaintext[:5]:
		print("[*] Key:", key.hex())
		print("[*] Plaintext:", plaintext)
		break
```

This way, after running the script 

## Task 2

To determine at which keyspace size the brute-force approach would become infeasible within reasonable time constraints, we measured that our system can test approximately 110,000 keys per second (using `tqdm`).

| offset | space         | time          |
| ------ | ------------- | ------------- |
| 1 byte | 2^8 = 256     | <1 second     |
| 2 byte | 2^16 = 65,536 | ~0.58 seconds |
| 3 byte | 2^24 ~ 16.7M  | ~2.5 minutes  |
| 4 byte | 2^32 ~ 4.3B   | ~10.5 hours   |
| 5 byte | 2^40 ~ 1.1T   | ~115 days     |
| 6 byte | 2^48 ~ 281T   | ~83 years     |

With 5 bytes or less, it is possible to break the encryption within 10 years. However, with 6 random bytes, brute forcing becomes clearly impractical without significant optimization or more computational resources.

## Task 3

Making a nonce secret by using only 1 byte and not transmitting it doesn’t meaningfully increase security.

Because guessing 2^8 = 256 possible nonce values per key is still trivial. If we can already brute force the reduced keyspace, multiplying by 256 adds lead to approximately 10.5 hours of wait-time, which is not extremely long.
