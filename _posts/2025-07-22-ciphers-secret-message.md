---
author: northmatrix
categories: 
math: true
media_subpath: /assets/img/rooms/ciphers-secret-message
comments: true
image:
  path: /logo.png
  alt: 
title: Ciphers Secret Message
tags: 
date created: 2025‑07‑22 17:43:18 +01:00
date modified: 2025‑08‑04 17:41:08 +01:00
---

## Overview

![](Pasted%20image%2020250804174107.png)

Ciphers Secret message is an easy ranked tryhackme room where we need to decrpyt some ciphertext to recover the plaintext.

## Code Analysis

Here is the code that was used to encrypt the plaintext and produce the following ciphertext: `a_up4qr_kaiaf0_bujktaz_qm_su4ux_cpbq_ETZ_rhrudm`

```python
from secret import FLAG

def enc(plaintext):
    return "".join(
        chr((ord(c) - (base := ord('A') if c.isupper() else ord('a')) + i) % 26 + base) 
        if c.isalpha() else c
        for i, c in enumerate(plaintext)
    )

with open("message.txt", "w") as f:
    f.write(enc(FLAG))
```

Looking at this code my initial idea was to write the decryption function in order to produce the ciphertext. However in the end i just decided to brute force it as that required less code my idea was to just cycle through all characters adding them to a string called result and then encryping that string and comparing it with characters in the ciphertext up to that index, repeating for each character in the ciphertext until i had discovered the entire plaintext.

```python
secret = "a_up4qr_kaiaf0_bujktaz_qm_su4ux_cpbq_ETZ_rhrudm"

def enc(plaintext):
    return "".join(
        chr((ord(c) - (base := ord('A') if c.isupper() else ord('a')) + i) % 26 + base) 
        if c.isalpha() else c
        for i, c in enumerate(plaintext)
    )

chars = [chr(i) for i in range(256)]
result = ""

for x in range(len(secret)):
    for c in chars:
        if enc(result + c) == secret[0:x+1]:
            result += c

print(result)
```
