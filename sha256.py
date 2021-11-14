"""
By: Taha Canturk
Finalized: nov 14, 2021

"""

import hashlib # test values

class sha256:
    """ default class initializer """
    def __init__(self, msg):
        self.convertToBytes = ''.join(format(ord(char), '08b') for char in msg)
        self.add1 = self.convertToBytes + '1'
        self.zFill = None
        len_bits = 512

        def r_rotate(lst, i):
            """ RIGHTROTATE """
            return lst[-i:] + lst[:-i]

        def XOR(x,y,z):
            """ Bitwise XOR """
            y = int(x, 2)^int(y, 2)^int(z, 2)
            return bin(y)[2:].zfill(len(x)) # zfill to 32

        def r_shift(a, RShft_n):
            """ Bitwise Right Shift """
            b_rightshiftedVal = bin(int(a)>>RShft_n)[2:].zfill(32) # zfill to 32
            return b_rightshiftedVal
        
        def b32(val):
            """ convert to 32 bit binary """
            return bin(val)[2:].zfill(32)
        
        # Ch(X, Y, Z) = (X ∧ Y ) ⊕ (~X ∧ Z)
        
        Ch = lambda x,y,z : bin(int(x,2)&int(y,2)^(~int(x,2))&int(z,2))[2:].zfill(32)
        # M aj(X, Y, Z) = (X ∧ Y ) ⊕ (X ∧ Z) ⊕ (Y ∧ Z)
        
        Maj = lambda x,y,z : bin(int(x,2)&int(y,2)^int(x,2)&int(z,2)^int(y,2) \
                                 &int(z,2))[2:].zfill(32)
        
        # self.zFill not a multiple of 512. self.addlen is a multiple of 512 
        # because it is the final byte value
        if len(self.add1) < len_bits:
            self.zFill = self.add1 + ''.zfill(len_bits - len(self.add1) - \
                                              len(format(len(self.convertToBytes), \
                                                         '08b')))
        else:
            padding = len_bits - len(self.add1) % len_bits
            self.zFill = self.add1 + ''.zfill(padding - 
                                              len(format(len(self.convertToBytes), \
                                                         '08b')))
        # add ascii value of length of msg's decimal value to zFill 
        # the length of self.addlen is always a multiple of 512
        self.addlen = self.zFill + format(len(self.convertToBytes), '08b')
        addtoW = [self.addlen[i:i+32] # seperated each bit by 32 into a list; Each entry = 32 bits.
                  for i in range(0, len(self.addlen), 32)]
        
        # length of self.W is always 64 no matter the length of message
        if len(addtoW) <= 64:
            self.W = addtoW + [''.zfill((64 - len(addtoW))*32)[f:f+32]
                               for f in range(0, 64 - len(addtoW))]

            # modify the zero-padded list items
            for zIndex in range(len(addtoW), len(self.W)):
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
        else:
            self.W = [(self.addlen + ''.zfill((64 - len(addtoW))*32))[i:i+32]
                      for i in range(0, 64)]
        
        
        # 2^32 times the square root of the first 8 primes
        h0 = 0x6a09e667
        h1 = 0xbb67ae85
        h2 = 0x3c6ef372
        h3 = 0xa54ff53a
        h4 = 0x510e527f
        h5 = 0x9b05688c
        h6 = 0x1f83d9ab
        h7 = 0x5be0cd19
        
        # 2^32 times the cube root of the first 64 primes
        k = [
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
        # b32 is a function defined earlier in the code.
        a = b32(h0)
        b = b32(h1)
        c = b32(h2)
        d = b32(h3)
        e = b32(h4)
        f = b32(h5)
        g = b32(h6)
        h = b32(h7)
        
        for i in range(0, 64):
            # sigma 1 = (Σ1): RotR(e, 6) ⊕ RotR(e, 11) ⊕ RotR(e, 25)
            
            S1 = XOR(r_rotate(e, 6), r_rotate(e, 11), r_rotate(e, 25))
            T1 = format((int(h,2) + int(S1,2) + int(Ch(e,f,g),2) + k[i] + \
                         int(self.W[i],2))%2**32,'08b').zfill(32)

            # sigma 0 = (Σ0): RotR(a, 2) ⊕ RotR(a, 13) ⊕ RotR(a, 22)

            S0 = XOR(r_rotate(a,2), r_rotate(a, 13), r_rotate(a, 22))
            
            # add sigma 0 to Maj(a,b,c). Addition is calculated mod 2**32
            T2 = bin((int(S0, 2) + int(Maj(a,b,c), 2))%2**32)[2:].zfill(32)
            
            # final values of the loop
            h = g
            g = f
            f = e
            e = bin((int(d,2) + int(T1,2))%2**32)[2:].zfill(32)
            d = c
            c = b
            b = a
            a = bin((int(T1,2) + int(T2,2))%2**32)[2:].zfill(32)

        # compute the hash values
        h0 = (h0 + int(a, 2))%2**32
        h1 = (h1 + int(b, 2))%2**32
        h2 = (h2 + int(c, 2))%2**32
        h3 = (h3 + int(d, 2))%2**32
        h4 = (h4 + int(e, 2))%2**32
        h5 = (h5 + int(f, 2))%2**32
        h6 = (h6 + int(g, 2))%2**32
        h7 = (h7 + int(h, 2))%2**32

        # digest final value in string format
        digest = lambda hVal : str(hex(hVal))[2:].zfill(8)
        
        self.hexdigest = digest(h0) + digest(h1) + digest(h2) + digest(h3) + \
                         digest(h4) + digest(h5) + digest(h6) + digest(h7)

        # when length is bigger than 56 its wrong
        test = hashlib.sha256(b"        "*70).hexdigest()
        
        raise Exception(f"\ntest:      {test}\nhexdigest: {self.hexdigest}")
        
    def __str__(self):
        return f"{self.hexdigest}"

print(sha256("        "*70))

# NOTICE: not done yet
