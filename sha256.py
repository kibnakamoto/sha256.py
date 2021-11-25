"""
By: Taha Canturk
Finalized: nov 16, 2021
info: github.com/kibnakamoto/sha256.py/blob/main/README.md
github: kibnakamoto
"""

import hashlib # test hash values

def r_rotate(lst, i):
    """ RIGHTROTATE """
    return lst[-i:] + lst[:-i]

def XOR(x,y,z):
    """ Bitwise XOR """
    y = int(x, 2)^int(y, 2)^int(z, 2)
    return bin(y)[2:].zfill(len(x)) # zfill to 32

def r_shift(a, RShft_n):
    """ Bitwise Right Shift """
    b_rightshiftedVal = bin(int(a)>>RShft_n)[2:].zfill(32)
    return b_rightshiftedVal

def b32(val):
    """ convert to 32 bit binary """
    return bin(val)[2:].zfill(32)

class sha256:
    """ default class initializer """
    def __init__(self, msg):
        self.convertToBytes = ''.join(format(ord(char), '08b') for char in msg)
        self.add1 = self.convertToBytes + '1'
        self.zFill = None
        
        # Choice(X, Y, Z) = (X ∧ Y ) ⊕ (~X ∧ Z)
        
        Ch = lambda x,y,z : bin(int(x,2)&int(y,2)^(~int(x,2))&int(z,2))[2:].zfill(32)
        # Majority(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
        
        Maj = lambda x,y,z : bin(int(x,2)&int(y,2)^int(x,2)&int(z,2)^int(y,2) \
                                 &int(z,2))[2:].zfill(32)
        
        # self.zFill is multiple of 512 - 64. self.addlen is a multiple of 512
        # because self.addlen is the final binary value
        padding = (512 - len(self.add1) - 64) % 512

        self.zFill = self.add1 + ''.zfill(padding)
        
        # add ascii value of length of msg's to zFill
        # the length of self.addlen is always a multiple of 512
        self.addlen = self.zFill + format(len(self.convertToBytes), '08b').zfill(64)[0:64]
        addtoW = [self.addlen[i:i+32] # seperated each 32 bits into a list; Each entry = 32 bits.
                  for i in range(0, len(self.addlen), 32)]
        
        # length of self.W is always 64 no matter the length of message
        self.W = addtoW + [''.zfill((64 - len(addtoW))*32)[i:i+32]
                          for i in range(0, 64 - len(addtoW))]
        
        # modify the zero-padded list items
        for zIndex in range(16, 64):
            # sigma 0 = (σ0): RotR(zIndex, 7) ) XOR RotR(zIndex, 18) XOR ShR(zIndex, 3)
            s0 = XOR(r_rotate(self.W[zIndex-15], 7), r_rotate(self.W[zIndex \
                                                                    -15], 18), \
                     r_shift(int(self.W[zIndex-15], 2), 3))
            
            # sigma 1 = (σ1): (zIndex, 17) XOR RotR(zIndex, 19) XOR ShR(zIndex, 10)
            s1 = XOR(r_rotate(self.W[zIndex-2], 17), \
                     r_rotate(self.W[zIndex-2], 19), r_shift(int(self.W[zIndex-2], \
                                                                 2), 10))
            # all addition is calculated mod 2**32
            self.W[zIndex] = format((int(self.W[zIndex-16],2) + int(s0,2) \
                             + int(self.W[zIndex-7], 2) + int(s1,2))%2**32,'08b').zfill(32)
        
        # 2^32 times the square root of the first 8 primes
        H = [None]*8
        HVals = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        
        for i in range(8):
            H[i] = HVals[i]
        
        # 2^32 times the cube root of the first 64 primes
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
        
        # initialize 32 bit binary values of the hash values
        V = [None]*8
        for i in range(8):
            V[i] = b32(H[i])
        
        for i in range(64):
            # sigma 1 = (Σ1): RotR(e, 6) ⊕ RotR(e, 11) ⊕ RotR(e, 25)
            
            S1 = XOR(r_rotate(V[4], 6), r_rotate(V[4], 11), r_rotate(V[4], 25))
            
            # Temp1 = add sigma 1 to Ch(e,f,g). Addition is calculated mod 2**32
            T1 = format((int(V[7],2) + int(S1,2) + int(Ch(V[4],V[5],V[6]),2) + K[i] + \
                         int(self.W[i],2))%2**32,'08b').zfill(32)
            
            # sigma 0 = (Σ0): RotR(a, 2) ⊕ RotR(a, 13) ⊕ RotR(a, 22)
            
            S0 = XOR(r_rotate(V[0],2), r_rotate(V[0], 13), r_rotate(V[0], 22))
            
            # Temp2 = add sigma 0 to Maj(a,b,c). Addition is calculated mod 2**32
            T2 = bin((int(S0, 2) + int(Maj(V[0],V[1],V[2]), 2))%2**32)[2:].zfill(32)
            
            # final values of the loop
            V[7] = V[6]
            V[6] = V[5]
            V[5] = V[4]
            V[4] = bin((int(V[3],2) + int(T1,2))%2**32)[2:].zfill(32)
            V[3] = V[2]
            V[2] = V[1]
            V[1] = V[0]
            V[0] = bin((int(T1,2) + int(T2,2))%2**32)[2:].zfill(32)
            
            # getting test vector values
            hValue = hex(int(V[7],2))[2:].zfill(0)
            gValue = hex(int(V[6],2))[2:].zfill(0)
            fValue = hex(int(V[5],2))[2:].zfill(0)
            eValue = hex(int(V[4],2))[2:].zfill(0)
            dValue = hex(int(V[3],2))[2:].zfill(0)
            cValue = hex(int(V[2],2))[2:].zfill(0)
            bValue = hex(int(V[1],2))[2:].zfill(0)
            aValue = hex(int(V[0],2))[2:].zfill(0)
        
        #           V[0]      V[1]     V[2]    V[3]     V[4]     V[5]     V[6]     V[7]
        # t = 0 :  7c20c838 85e655d6 417a1795 3363376a 4670ae6e 76e09589 cac5f811 cc4b32c1
        # t = 1 :  7c3c0f86 7c20c838 85e655d6 417a1795 8c51be64 4670ae6e 76e09589 cac5f811
        # t = 2 :  fd1eebdc 7c3c0f86 7c20c838 85e655d6 af71b9ea 8c51be64 4670ae6e 76e09589
        # t = 3 :  f268faa9 fd1eebdc 7c3c0f86 7c20c838 e20362ef af71b9ea 8c51be64 4670ae6e
        # t = 4 :  185a5d79 f268faa9 fd1eebdc 7c3c0f86 8dff3001 e20362ef af71b9ea 8c51be64
        # t = 5 :  3eeb6c06 185a5d79 f268faa9 fd1eebdc fe20cda6 8dff3001 e20362ef af71b9ea
        # t = 6 :  89bba3f1 3eeb6c06 185a5d79 f268faa9 0a34df03 fe20cda6 8dff3001 e20362ef
        # t = 7 :  bf9a93a0 89bba3f1 3eeb6c06 185a5d79 059abdd1 0a34df03 fe20cda6 8dff3001
        # t = 8 :  2c096744 bf9a93a0 89bba3f1 3eeb6c06 abfa465b 059abdd1 0a34df03 fe20cda6
        # t = 9 :  2d964e86 2c096744 bf9a93a0 89bba3f1 aa27ed82 abfa465b 059abdd1 0a34df03
        # t = 10 : 5b35025b 2d964e86 2c096744 bf9a93a0 10e77723 aa27ed82 abfa465b 059abdd1
        # t = 11 : 5eb4ec40 5b35025b 2d964e86 2c096744 e11b4548 10e77723 aa27ed82 abfa465b
        # t = 12 : 35ee996d 5eb4ec40 5b35025b 2d964e86 5c24e2a2 e11b4548 10e77723 aa27ed82
        # t = 13 : d74080fa 35ee996d 5eb4ec40 5b35025b 68aa893f 5c24e2a2 e11b4548 10e77723
        # t = 14 : 0cea5cbc d74080fa 35ee996d 5eb4ec40 60356548 68aa893f 5c24e2a2 e11b4548
        # t = 15 : 16a8cc79 0cea5cbc d74080fa 35ee996d 0fcb1f6f 60356548 68aa893f 5c24e2a2
        # t = 16 : f16f634e 16a8cc79 0cea5cbc d74080fa 8b21cdc1 0fcb1f6f 60356548 68aa893f
        # t = 17 : 23dcb6c2 f16f634e 16a8cc79 0cea5cbc ca9182d3 8b21cdc1 0fcb1f6f 60356548
        # t = 18 : dcff40fd 23dcb6c2 f16f634e 16a8cc79 69bf7b95 ca9182d3 8b21cdc1 0fcb1f6f
        # t = 19 : 76f1a2bc dcff40fd 23dcb6c2 f16f634e 0dc84bb1 69bf7b95 ca9182d3 8b21cdc1
        # t = 20 : 20aad899 76f1a2bc dcff40fd 23dcb6c2 cc4769f2 0dc84bb1 69bf7b95 ca9182d3
        # t = 21 : d44dc81a 20aad899 76f1a2bc dcff40fd 5bace62d cc4769f2 0dc84bb1 69bf7b95
        # t = 22 : f13ae55b d44dc81a 20aad899 76f1a2bc 966aa287 5bace62d cc4769f2 0dc84bb1
        # t = 23 : a4195b91 f13ae55b d44dc81a 20aad899 eddbd6ed 966aa287 5bace62d cc4769f2
        # t = 24 : 4984fa79 a4195b91 f13ae55b d44dc81a a530d939 eddbd6ed 966aa287 5bace62d
        # t = 25 : aa6cb982 4984fa79 a4195b91 f13ae55b 0b5eeea4 a530d939 eddbd6ed 966aa287
        # t = 26 : 9450fbbc aa6cb982 4984fa79 a4195b91 09166dda 0b5eeea4 a530d939 eddbd6ed
        # t = 27 : 0d936bab 9450fbbc aa6cb982 4984fa79 6e495d4b 09166dda 0b5eeea4 a530d939
        # t = 28 : d958b529 0d936bab 9450fbbc aa6cb982 c2fa99b1 6e495d4b 09166dda 0b5eeea4
        # t = 29 : 1cfa5eb0 d958b529 0d936bab 9450fbbc 6c49db9f c2fa99b1 6e495d4b 09166dda
        # t = 30 : 02ef3a5f 1cfa5eb0 d958b529 0d936bab 5da10665 6c49db9f c2fa99b1 6e495d4b
        # t = 31 : b0eab1c5 02ef3a5f 1cfa5eb0 d958b529 f6d93952 5da10665 6c49db9f c2fa99b1
        # t = 32 : 0bfba73c b0eab1c5 02ef3a5f 1cfa5eb0 8b99e3a9 f6d93952 5da10665 6c49db9f
        # t = 33 : 4bd1df96 0bfba73c b0eab1c5 02ef3a5f 905e44ac 8b99e3a9 f6d93952 5da10665
        # t = 34 : 9907f1b6 4bd1df96 0bfba73c b0eab1c5 66c3043d 905e44ac 8b99e3a9 f6d93952
        # t = 35 : ecde4e0d 9907f1b6 4bd1df96 0bfba73c 5dc119e6 66c3043d 905e44ac 8b99e3a9
        # t = 36 : 2f11c939 ecde4e0d 9907f1b6 4bd1df96 fed4ce1d 5dc119e6 66c3043d 905e44ac
        # t = 37 : d949682b 2f11c939 ecde4e0d 9907f1b6 32d99008 fed4ce1d 5dc119e6 66c3043d
        # t = 38 : adca7a96 d949682b 2f11c939 ecde4e0d c6cce4ff 32d99008 fed4ce1d 5dc119e6
        # t = 39 : 221b8a5a adca7a96 d949682b 2f11c939 0b82c5eb c6cce4ff 32d99008 fed4ce1d
        # t = 40 : 12d97845 221b8a5a adca7a96 d949682b e4213ca2 0b82c5eb c6cce4ff 32d99008
        # t = 41 : 2c794876 12d97845 221b8a5a adca7a96 ff6759ba e4213ca2 0b82c5eb c6cce4ff
        # t = 42 : 8300fca2 2c794876 12d97845 221b8a5a e0e3457c ff6759ba e4213ca2 0b82c5eb
        # t = 43 : f2ad6322 8300fca2 2c794876 12d97845 cc48c7f3 e0e3457c ff6759ba e4213ca2
        # t = 44 : 0f154e11 f2ad6322 8300fca2 2c794876 6f9517cb cc48c7f3 e0e3457c ff6759ba
        # t = 45 : 104a7db4 0f154e11 f2ad6322 8300fca2 5348e8f6 6f9517cb cc48c7f3 e0e3457c
        # t = 46 : 0b3303a7 104a7db4 0f154e11 f2ad6322 bbe1c39a 5348e8f6 6f9517cb cc48c7f3
        # t = 47 : d7354d5b 0b3303a7 104a7db4 0f154e11 aad55b6b bbe1c39a 5348e8f6 6f9517cb
        # t = 48 : b736d7a6 d7354d5b 0b3303a7 104a7db4 68f25260 aad55b6b bbe1c39a 5348e8f6
        # t = 49 : 2748e5ec b736d7a6 d7354d5b 0b3303a7 d4b58576 68f25260 aad55b6b bbe1c39a
        # t = 50 : d8aabcf9 2748e5ec b736d7a6 d7354d5b 27844711 d4b58576 68f25260 aad55b6b
        # t = 51 : 1a6bcf6a d8aabcf9 2748e5ec b736d7a6 ff5e99d0 27844711 d4b58576 68f25260
        # t = 52 : 4eca6fa0 1a6bcf6a d8aabcf9 2748e5ec 989ed071 ff5e99d0 27844711 d4b58576
        # t = 53 : ec02560a 4eca6fa0 1a6bcf6a d8aabcf9 7151df8e 989ed071 ff5e99d0 27844711
        # t = 54 : d9f0c115 ec02560a 4eca6fa0 1a6bcf6a 624150c4 7151df8e 989ed071 ff5e99d0
        # t = 55 : 92952710 d9f0c115 ec02560a 4eca6fa0 226806d6 624150c4 7151df8e 989ed071
        # t = 56 : 20d4d0e4 92952710 d9f0c115 ec02560a 4e515a4d 226806d6 624150c4 7151df8e
        # t = 57 : 4348eb1f 20d4d0e4 92952710 d9f0c115 c21eddf9 4e515a4d 226806d6 624150c4
        # t = 58 : 286fe5f0 4348eb1f 20d4d0e4 92952710 54076664 c21eddf9 4e515a4d 226806d6
        # t = 59 : 1c4cddd9 286fe5f0 4348eb1f 20d4d0e4 f487a853 54076664 c21eddf9 4e515a4d
        # t = 60 : a9f181dd 1c4cddd9 286fe5f0 4348eb1f 27ccb387 f487a853 54076664 c21eddf9
        # t = 61 : b25cef29 a9f181dd 1c4cddd9 286fe5f0 2aa1bb13 27ccb387 f487a853 54076664
        # t = 62 : 908c2123 b25cef29 a9f181dd 1c4cddd9 9a392956 2aa1bb13 27ccb387 f487a853
        # t = 63 : 9ea7148b 908c2123 b25cef29 a9f181dd 2c5c4ed0 9a392956 2aa1bb13 27ccb387
        
        # t = 0 in block 2 uses the value of self.hexdigest for iteration. 
        # block 2 = self.hexdigest value from block 1
        
        # compute the hash values
        for i in range(8):
            H[i] = (H[i] + int(V[i], 2))%2**32
        
        # hexadecimal final digest in string format
        digest = lambda hVal : str(hex(hVal))[2:].zfill(8)
        
        self.hexdigest = digest(H[0]) + digest(H[1]) + digest(H[2]) + digest(H[3]) + \
                       digest(H[4]) + digest(H[5]) + digest(H[6]) + digest(H[7])
        
        self.test = hashlib.sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hexdigest()
        
        assert self.test == self.hexdigest, \
              f"\ntest:\t   {self.test}\nhexdigest: {self.hexdigest}"
        
    def __str__(self):
        return f"\ntest:\t   {self.test}\nhexdigest: {self.hexdigest}"

# ba7816bf8f01cfea414140de5dae2223bda12ae1a5324sfdserew3ra
print(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

# Notice: won't work if message length is bigger than 56 so it's being debugged.
