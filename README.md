# sha256.py
This program of the sha256 algorithm in python doesn't use any modules.

The purpose of the code was to better understand cryptographic algorithms and learn how to implement hashing algorithms since there isn't standard library available for algorithms like this in c++.

This code was written in: nov 14, 2021. 

I am/was 15 when I wrote this code.

By: Taha Canturk (Kibnakamoto in github)

Supports multi-block processing

Added multi-block processing in Feb 21, 2022

Information: Sha256 algorithm is a hashing algorithm made by National security agency in 2001. It is the 256-bit SHA-2 hashing algorithm.

The operations used:

  XOR(): ^ (⊕)
  
  rightrotate:  (r_rotate function)
  
  rightshift: (r_shift function)
  
  bitwise and = &
  
  bitwise complement = ~


all binary numbers are used with base 2.

X, Y, Z = w[index]


Equations:
  Ch(X, Y, Z) = (X & Y ) ⊕ (~X & Z)
  
  Maj(X, Y, Z) = (X & Y ) ⊕ (X & Z) ⊕ (Y & Z)
  
  capital sigma 0 = Σ0: r_rotate(X, 2) ⊕ r_rotate(X, 13) ⊕ r_rotate(X, 22)
  
  capital sigma 1 = Σ1: r_rotate(e, 6) ⊕ r_rotate(e, 11) ⊕ r_rotate(e, 25)
  
  small sigma 0 = σ0: r_rotate(X, 7) ⊕ r_rotate(X, 18) ⊕ r_shift(X, 3)
  
  small sigma 1 = σ1: r_rotate(X, 17) ⊕ r_rotate(X, 19) ⊕ r_shift(X, 10)
  
  T1 = h + Σ1(e) + Ch(e, f, g) + K[i] + W[i]
  
  T2 = Σ0(a) + Maj(a, b, c)
  
  
  
  constants:
        # 2**32 times the cube root of the first 64 primes
        
        K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
        
        # 2**32 times the square root of the first 8 primes
        # hash values
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19
        
