+++
title = "AES ECB Implemented In Rust"
date = "2025-08-19T23:26:01+01:00"
author = "Northmatrix"
tags = ["Crypto", "Rust"]
description = "128 Bit AES EBC Implemented in the rust programming language"
coverImg="cover.webp"
readingTime = true
+++

# AES in Rust

## Introduction

AES (advanced encryption standard) also known as Rijndael is a specification for the encryption of electronic data established by the US National institute of standards and technology NIST in 2001.  
AES is a block cipher with a block size of 128 bits that supports 3 key sizes of length 128,192 and 256 bits.  
AES is used everywhere in information technology from SSH to HTTPS

### Project Goal

In this tutorial we will be implementing 128 bit Aes encryption

> Do not use any untested encryption in production for a secure and tested alternative use [Aes-Gcm](https://crates.io/crates/aes-gcm)

## Encryption Overview

Aes encryption can be separated into 4 steps allowing us to easier understand the problem.

1. Generating Round Keys
2. Adding Round Key to block
3. For each round (except last)

- Substitute Block Bytes with Sbox Values
- Shift the rows of the Block
- Mix the Columns
- Add Round Key to Block

4. Final Round(no mix cols)

- Add Round Key to block
- Shift the rows of the block
- Add round key to block

As we can see here there are likely to be some functions which we will need to implement such as

- sub_bytes()
- shift_rows()
- mix_cols()
- add_round_keys()
- generate_round_keys()

In the next step you will learn to implement these functions, as well as understandnig what they do and any maths required to understand it.

### Sub Bytes

The SBOX (substituon box) is a bijective map that maps each input byte to a corrosponding output byte below is this substitution box that is computed in such a way that it adds nonlinearity thus significantly improving resilliance to linear and differential cryptoanalysis attacks.

```rust
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,0x16]
```

here is the rust code which mutably iterates over the block substituting each byte for the corrosponding output value defined by the sbox.

```rust
fn sub_bytes(state: &mut [u8;16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}
```

### Shift Rows

the **shift rows** operation can be represented as a map $M$ which transforms a $4 \times 4$ matrix, defined below:

$ M: \mathbb{B}^{4 \times 4} \to \mathbb{B}^{4 \times 4} $

$ \mathbb{B} $ represents the set of binary digits.

The map M takes a matrix, and transforms it cyclicly by shifting the ith rows i places to the left, this is shown below.

$$
\begin{aligned}
M\left(\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}\right)
&=
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_5 & b_9 & b_{13} & b_1 \\
b_{10} & b_{14} & b_2 & b_6 \\
b_{15} & b_3 & b_7 & b_{11}
\end{bmatrix}
\end{aligned}
$$

this helps increase the complexity of the cipher by ensuring the influence of each byte is spread across multiple columns  
this combined with the function mix_cols which will be covered later helps contribute to the diffusion of the cipher  
below i have written this transformation in rust.

```rust
fn shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}
```

this works by passing a mutable reference the block in its current state and creating a temporary copy where the values can be read from and assigned to the state  
which changes it in place.

## Mix Cols

The **mix cols** operation can be represented as linear transformation $ P $ in the finite field $ GF(2^8) $ that transforms each column in the block  
before we cover ths transformation we first have to understsnd galios fields $ GF(2^8) $.

### $ GF(2^8) $ Galios Field

- $ GF(2^8) $ is a finite field with $ 2^8 $ elements.
- The elements of this field are 8 bit numbers (bytes) represented as binary polynomials.
- Addition in $ GF(2^8) $ is defined as bitwise XOR between two bytes as $ a \oplus b $.
- Multiplication in $ GF(2^8) $ involves standard polynomial multiplication followed by a reduction moduolo an irreducible polynomial of degree 8 one such polynomial is $ x^8 + x^4 + x^3 +x + 1 $
- Relation between binary form and polynomial form:  
  $ b_7b_6b_5b_4b_3b_2b_1b_0 = b_7x^7 + b_6x^6 + b_5x^5 + b_4x^4 + b_3x^3 + b_2x^2 + b_1x + b_0 $

### Example in $ GF(2^8) $

1. **Problem Setup**:  
   We will now show the multiplication of 255 by 3 in $GF(2^8)$:  
   $255 \times 3$

2. **Polynomial Form**:  
   We will now write each in its polynomial from:  
   $255 = x^7 + x^6 + x^5 + x^4 + x^3 + x^2 + x + 1$  
   $3 = x + 1$

3. **Polynomial Multiplication**:  
   We will now multiply both polynomias together:  
   $ a(x) = x^7+x^6+x^5+x^5+x^4+x^3+x^2+x+1 $  
   $ b(x) = x+1 $  
   $ a(x)b(x) = x^8+x^7+x^6+x^5+x^4+x^3+x^2+x+x^7+x^6+x^5+x^4+x^3+x^2+x^1+1 $

4. **Simplification**:  
   We can now rearange this and use the fact that $ x^n \oplus x^n = 0 $:  
   $x^8 + (x^7\oplus x^7) +(x^6\oplus x^6)+(x^5\oplus x^5)+(x^4\oplus x^4)+(x^3\oplus x^3)+(x^2\oplus x^2)+(x^1\oplus x^1) + 1$  
   This will give us the following:  
   $ x^8 + 1 $

5. **Modulo Reduction**:  
   But this does not belong in the field $ GF(2^8) $ so we must reduce modulo the polynomial:  
   $ x^8+x^4+x^3+x^1+1 $  
   We can use the following equivilance to reduce the polynomial:  
   $ x^8 \equiv x^4 + x^3 + x^1 + 1\space(mod \space x^8+x^4+x^3+x^1) $

6. **Simplification**:  
   This is the reduced polynomial:  
   $ x^4 + x^3 +x^1 + 1 + 1 $  
   We can now simplify it using additive property of the field:  
   $ x^4+x^3+x^1+(1 \oplus 1) = x^4+x^3+x $

7. **Converting**:  
   Converting to binary gives us `00011010` and in denary `26`:  
   Thus giving us the following result:  
   $ 255 \times 3 = 26 $ in $ GF(2^8) $

> The operators + and $ \oplus $ are interchangeable ans used only to clarify when XOR is being used  
> {:.prompt-info }

### Rust Implementation

```rust
fn gal_mul(mut a: u8, mut b: u8) -> u8 {
   //initially sets result to 0
    let mut result = 0u8;
    //loops while b is greater than 0
    while b > 0 {
        // checks if least significant bit is on and executes below codeif it is
        if b & 1 != 0 {
            // XOR's the result with a i.e addition in GF(2^8)
            result ^= a;
        }
        // We than check if the most significant bit is on
        let carry = a & 0x80;
        // Then we perform a binary shift to the left i.e multiplication by 2 i.e x in polynomial form
        a <<= 1;
        // If the most significant bit was on we the XOR a with the reduction polynomial x^8+x^4+x^3+x^1+1 which is 0x1b in hexadecimal
        // thus keeping a and by extension the result in GF(2^8) by not allowing degree to exceed 7 i.e <= 7
        if carry != 0 {
            a ^= 0x1b;
        }
        // Finally we shift b one place to the right i.e division by 2 or x
        b >>= 1;
    }
    result
}
```

### Explanation of Galios Multiplication Function Gal_Mul()

#### Idea Behind Function

The above function factors out x from the polynomial b(x) and multiplies it to a(x) this doesnt effect the result as:

$ x \cdot a(x) \cdot x^{-1} \cdot b(x) = a(x)b(x) $

So now

$ a(x) = x \cdot a(x) $ And $ b(x) = x^{-1} \cdot b(x) $

If a(x) ever exceeds degree 8 it is reduced modulo the polynomial `0x1b` i.e the reduction polynomial we looked at before

This repeats until b(x) is no longer divisible by x which implies the polynomial is constant

at this stage we can then add a(x) to the result and remove the 1 by performing a right shift on b(x)

once b = 0 the result will return.

#### Code Trace

1. $ a(x) = x^3+x^2 $, $ b(x) = x^2 + x $, $ r = 0 $
2. $ a(x) = x^4 + x^3 $, $ b(x) = x + 1 $, $ r = x^3+x^2 $
3. $ a(x) = x^5+ x^4 $, $ b(x) = 1 $, $ r = x^3 + x^2 + x^4 + x^3 $
4. $ a(x) = x^6+x^5 $, $ b(x) = 0 $, $ r = x^3 + x^2 + x^4 + x^3 + x^5 + x^4 $
5. $ b(x) = 0 $ so $ r $ is returned $ r = x^3 + x^2 + x^4 + x^3 +x^5 + x^4 = x^5 + (x^4 \oplus x^4) + (x^3 \oplus x^3) + x^2 = x^5 + 0 + 0 + x^2 = x^5 + x^2 $

## Now onto the Transformation

Now that we have covered the finite field $ GF(2^8) $ we can continue to implement the transformation $ P $ which is defined below:

$ P: \mathbb{B}^{4 \times 1} \to \mathbb{B}^{4 \times 1} $

$$
\begin{aligned}
P\left(\begin{bmatrix} s_0 \\ s_1 \\ s_2 \\ s_3 \end{bmatrix}\right)
&=
\begin{bmatrix}
02 & 03 & 01 & 01 \\
01 & 02 & 03 & 01 \\
01 & 01 & 02 & 03 \\
03 & 01 & 01 & 02
\end{bmatrix}
\begin{bmatrix}
s_0 \\
s_1 \\
s_2 \\
s_3
\end{bmatrix}
&=
\begin{bmatrix}
(02 \cdot s_0) \oplus (03 \cdot s_1) \oplus (01 \cdot s_2) \oplus (01 \cdot s_3) \\
(01 \cdot s_0) \oplus (02 \cdot s_1) \oplus (03 \cdot s_2) \oplus (01 \cdot s_3) \\
(01 \cdot s_0) \oplus (01 \cdot s_1) \oplus (02 \cdot s_2) \oplus (03 \cdot s_3) \\
(03 \cdot s_0) \oplus (01 \cdot s_1) \oplus (01 \cdot s_2) \oplus (02 \cdot s_3)
\end{bmatrix}\end{aligned}
$$

below i have written this operation in rust.

```rust
fn mix_cols(state: &mut [u8; 16]) {
    let temp = *state;
    for col in 0..4 {
        let offset = col * 4;
        let s = [
            temp[offset],
            temp[offset + 1],
            temp[offset + 2],
            temp[offset + 3],
        ];

        state[offset] = gal_mul(s[0], 0x02) ^ gal_mul(s[1], 0x03) ^ s[2] ^ s[3];
        state[offset + 1] = s[0] ^ gal_mul(s[1], 0x02) ^ gal_mul(s[2], 0x03) ^ s[3];
        state[offset + 2] = s[0] ^ s[1] ^ gal_mul(s[2], 0x02) ^ gal_mul(s[3], 0x03);
        state[offset + 3] = gal_mul(s[0], 0x03) ^ s[1] ^ s[2] ^ gal_mul(s[3], 0x02);
    }
}
```

## Add Round Key

Adding the **Round Key** is fairly simple it is just the 128 bit block XOR with the 128 bit round key

```rust
fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(key.iter()) {
        *s ^= k;
    }
}
```

## AES-128 Key Schedule

In AES-128, the key schedule expands the initial 128-bit key into 11 round keys (for 10 rounds), each 128 bits long.

### Key Expansion Overview

- **Initial key**: $K$ is 128 bits, represented as four 32-bit words $W_0, W_1, W_2, W_3$.
- **Round keys**: The original key is the first round key and each subsequent round key is generated as 4 new words
- **Total words**: $4 \times 11 = 44$ words in total, with 4 words for each of the 11 round keys.

### Key Expansion Steps

The AES key schedule uses:

**SubWord**: A function that applies the AES SBOX (non-linear substitution) to each byte of the word.

$\text{SubWord}(W) = \text{Sbox}(W)$

**ShiftWord**: A function that cyclicaly rotates the bytes of a word left by one position.

$\text{ShiftWord}([b_0, b_1, b_2, b_3]) = [b_1, b_2, b_3, b_0]$

**Round Constant (RCON)**: A constant that is XORed with a word.

$RCON[i] = \text{[0x02}^{i-1}, 0x00, 0x00, 0x00]$

### Round Key Generation

**Initial Words**: The first four words $W_0, W_1, W_2, W_3$ come directly from the original key $K$.
**Next Words**: For $i = 4, 5, \dots, 43$:

If $i$ is a multiple of 4, calculate:

$W_i = W_{i-4} \oplus \text{SubWord}(\text{ShiftWord}(W_{i-1})) \oplus RCON[i/4]$

Otherwise:

$W_i = W_{i-4} \oplus W_{i-1}$

```rust
//Here is a pre-computed list that contains the first byte for each Round Constant
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn generate_round_keys(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys = [[0u8; 16]; 11];
    //sets the first round key to the original key
    round_keys[0].copy_from_slice(key);
    //creates a temporary word that we can perform operations on
    let mut temp = [0u8; 4];
    for i in 1..11 {
        //sets the temp value to  the last word of the previous round key
        temp.copy_from_slice(&round_keys[i - 1][12..16]);
        //rotares the temp left by 1 value
        temp.rotate_left(1);
        //substitue each byte in the word using SBOX lookup table
        for byte in &mut temp {
            *byte = SBOX[*byte as usize];
        }
        //XOR's the temp word with the Round constant for the round
        temp[0] ^= RCON[i - 1];
        //loops over the 4 words in the round key applying the following operations
        for j in 0..4 {
            //the round keys first word is a multiple of 4 so we xor with the temp
            // which is SubWord(ShiftWord(W_i)) xor RCON[i] thus mirroring the equation above
            round_keys[i][j] = round_keys[i - 1][j] ^ temp[j];
            //for the next 3 words with simply XOR with the previous word of the current round key
            //and the word in the same position on the previous round keys (W_i-1 and W_i_4) corrospondingly
            // we repeat this 4 times for each byte of the 4 words
            round_keys[i][j + 4] = round_keys[i - 1][j + 4] ^ round_keys[i][j];
            round_keys[i][j + 8] = round_keys[i - 1][j + 8] ^ round_keys[i][j + 4];
            round_keys[i][j + 12] = round_keys[i - 1][j + 12] ^ round_keys[i][j + 8];
        }
    }

    round_keys
}
```

## Encrypting A Block

We can now combine this all together to implement the block encryption function shown below

```rust
pub fn block_encrypt(state: &mut [u8; 16], key: &[u8; 16]) {
    let round_keys = generate_round_keys(key);
    add_round_key(state, &round_keys[0]);
    for round in round_keys.iter().take(10).skip(1) {
        sub_bytes(state);
        shift_rows(state);
        mix_cols(state);
        add_round_key(state, round);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[10]);
}
```

## Decryption Overview

Now that we can encrypt this data we have finished this part of the cipher, but without a way to restore the ciphertext back to plaintext this entire function is useless  
that is why next we will work on decrypting a block todo this we will need to implement all the above functions inverse operations, this includes

- add_round_key
- inv_sub_bytes
- inv_shift_rows
- inv_mix_cols

Fortunatley this is possible with minor adjustments to the normalfunctions, additionally the function add_key is its own inverse the proof for this is below

### Add_key Inverse Proof

The Add_key function simply performs Xor operation on each bit from the block with each bit of the key as both are 128 bits, so to prove this function is self invertible all we need to show is that xor itself is self invertible, this is shown below.

suppose b and k are both elements from the set {0,1}, then xor is represented below

$ b \oplus k $

now when we again xor b with k again we get the following

$ (b \oplus k) \oplus k $

since xor is associotive this is the same as the following

$ b \oplus (k \oplus k) $

but we know that anything value xored with itself is 0 so this is the same as

$ b \oplus 0 $

again using the above fact this is the same as

$ b $

This proves that xor is self invertible and thus the add_key function

Now we will begin implementing the inverse of the functions specified above.

### Inv_Sub_Bytes

to implement this function we will first need to construct the inverse of the SBOX this can simply be achieved by setting the index of each value in the sbox to its value and the value of each value in the sbox to its index below is a table constructed this way

```rust
const INVSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];
```

Now we can simply iterate through the block again substituting each byte again, below is this function

```rust
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INVSBOX[*byte as usize]
    }
}
```

### Inv Sift Rows

To implement this function we need to take a look back at what the original function did we can recall that it shifted the ith row i places to the left, so the inverse of this would be shifting th ith row i places to the right note that indexing the rows start at 0 so the first row is shifted 0 rows to the right.

$$
\begin{aligned}M\left(
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_1 & b_5 & b_9 & b_{13} \\
b_2 & b_6 & b_{10} & b_{14} \\
b_3 & b_7 & b_{11} & b_{15}
\end{bmatrix}
\right)
&=
\begin{bmatrix}
b_0 & b_4 & b_8 & b_{12} \\
b_{13} & b_1 & b_5 & b_9 \\
b_{10} & b_{14} & b_2 & b_6 \\
b_7 & b_{11} & b_{15} & b_3
\end{bmatrix}\end{aligned}
$$

```rust
fn inv_shift_rows(state: &mut [u8; 16]) {
    let temp = *state;
    state[0] = temp[0];
    state[4] = temp[4];
    state[8] = temp[8];
    state[12] = temp[12];
    state[1] = temp[13];
    state[2] = temp[10];
    state[3] = temp[7];
    state[5] = temp[1];
    state[6] = temp[14];
    state[7] = temp[11];
    state[9] = temp[5];
    state[10] = temp[2];
    state[11] = temp[15];
    state[13] = temp[9];
    state[14] = temp[6];
    state[15] = temp[3];
}
```

### Inverse Mix Cols

The inverse mix cols function is simply a linear transformation $ M^{-1} $ applied to the current state of the block calculating this map is out of the scope here but it is simply the inverse of M in the field $ GF(2^8) $ below is the code that we can use to achieve this

```rust
fn inv_mix_cols(state: &mut [u8; 16]) {
    let temp = *state;
    for col in 0..4 {
        let offset = col * 4;
        let s = [
            temp[offset],
            temp[offset + 1],
            temp[offset + 2],
            temp[offset + 3],
        ];

        state[offset] =
            gal_mul(s[0], 0x0e) ^ gal_mul(s[1], 0x0b) ^ gal_mul(s[2], 0x0d) ^ gal_mul(s[3], 0x09);
        state[offset + 1] =
            gal_mul(s[0], 0x09) ^ gal_mul(s[1], 0x0e) ^ gal_mul(s[2], 0x0b) ^ gal_mul(s[3], 0x0d);
        state[offset + 2] =
            gal_mul(s[0], 0x0d) ^ gal_mul(s[1], 0x09) ^ gal_mul(s[2], 0x0e) ^ gal_mul(s[3], 0x0b);
        state[offset + 3] =
            gal_mul(s[0], 0x0b) ^ gal_mul(s[1], 0x0d) ^ gal_mul(s[2], 0x09) ^ gal_mul(s[3], 0x0e);
    }
}
```

### Decrypting the Block

Now we have made all the operations that need to be appliedin the decryption step we can simply implement it note that in the decrypting process we are just applying the operations in the opposite order of the enrcyption processes thus undoing it and returning to our original plaintext  
so instead of starting at round 1 we start at round 11 (index 10 because 0 based indexing) for the initial adding of the round key and then iterate the main block with round keys 10 to 2 and then apply the final round 1, this is the inverse of the enrcypting function and thus will return us with our original block

```rust
pub fn block_decrypt(state: &mut [u8; 16], key: &[u8; 16]) {
    let round_keys = generate_round_keys(key);
    add_round_key(state, &round_keys[10]);
    for round in round_keys.iter().take(10).skip(1).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round);
        inv_mix_cols(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &round_keys[0]);
}
```

## Finishing up

Now we have completely finished implementing the encryption and decryption of blocks and can now being testing our application below are a series of tests written to ensure that each operation works correctly as well as using some test vectors from this nist pdf  
<https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf>

```rust
#[cfg(test)]
mod tests {
    use hex_lit::hex;

    use super::*;
    #[test]
    fn test_shift_rows() {
        let mut state = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let expected = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let original = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        shift_rows(&mut state);
        assert_eq!(state, expected);
        inv_shift_rows(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_byte_sub() {
        let original = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let mut state = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        sub_bytes(&mut state);
        inv_sub_bytes(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_gal_mul() {
        //verified by hand
        assert_eq!(gal_mul(2, 2), 4);
        assert_eq!(gal_mul(6, 3), 10);
        assert_eq!(gal_mul(7, 12), 36);
        assert_eq!(gal_mul(12, 12), 80);
    }
    #[test]
    fn test_col_shift() {
        //Note this works i calculated the matrix by hand
        let mut state = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        let original = [1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4];
        mix_cols(&mut state);
        inv_mix_cols(&mut state);
        assert_eq!(state, original);
    }
    #[test]
    fn test_encryption() {
        //values taken from test vector https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mut plaintext = hex!("00112233445566778899aabbccddeeff");
        let expected = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
        block_encrypt(&mut plaintext, &key);
        assert_eq!(plaintext, expected);
    }
    #[test]
    fn test_decryption() {
        //values taken from test vector https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf
        let key = hex!("000102030405060708090a0b0c0d0e0f");
        let mut ciphertext = hex!("69c4e0d86a7b0430d8cdb78070b4c55a");
        let expected = hex!("00112233445566778899aabbccddeeff");
        block_decrypt(&mut ciphertext, &key);
        assert_eq!(ciphertext, expected);
    }
}
```
