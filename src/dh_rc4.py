
import os
from binascii import *
from hashlib import *

dh_modulus=0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b13b202ffffffffffffffff

class rc4():
    def __init__(self, key):
        self.S = S = range(256)

        #KSA Phase
        j = 0
        for i in range(256):
            j = (j + S[i] + ord( key[i % len(key)] )) % 256
            S[i] , S[j] = S[j] , S[i]

        self.i = self.j = 0

    def crypt(self, data):
        out = []
        
        S, i, j = self.S, self.i, self.j
        #PRGA Phase
        for char in data:
            i = ( i + 1 ) % 256
            j = ( j + S[i] ) % 256
            S[i] , S[j] = S[j] , S[i]
            out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

        self.i, self.j = i, j

        return ''.join(out)


class transport_stream():
    def __init__(self, s):
        self.sock = s
        sk = self.handshake()
        self.rc4_out = rc4(sk)
        self.rc4_in = rc4(chr(ord(sk[0])+1) + sk[1:]) # XXX: increment one byte only, or treat as a number?

    def param(self):
        return int(hexlify(os.urandom(48)), 16)

    def handshake(self):
        a = self.param()
        pa = pow(2, a, dh_modulus)
        mpa = unhexlify("%096x" % pa)
        self.sock.send(mpa)
        mpb = self.sock.recv(1024)
        pb = int(hexlify(mpb[:48]), 16)
        pab = pow(pb, a, dh_modulus)
        sk = unhexlify("%096x" % pab)
        print "dh sk=" + hexlify(sk)
        h=md5("O" + sk).digest()
        h=h[:8]
        self.sock.send(h)
        return sk

    def recv(self, l):
        b=''

        while len(b) < l:
            nb=self.sock.recv(l-len(b))
            if not nb:
                raise Exception("eof")
            b += nb

        return self.rc4_in.crypt(b)

    def send(self, b):
        return self.sock.send(self.rc4_out.crypt(b))
