
import os
from struct import pack, unpack
from binascii import *
from hashlib import *
from Crypto.Cipher import AES

import pack41, pack42
from things import *
from cred import *

login_key = 0xa8f223612f4f5fc81ef1ca5e310b0b21532a72df6c1af0fbec87304aec983aab5d74a14cc72e53ef7752a248c0e5abe09484b597692015e796350989c88b3cae140ca82ccd9914e540468cf0edb35dcba4c352890e7a9eafac550b3978627651ad0a804f385ef5f4093ac6ee66b23e1f8202c61c6c0375eeb713852397ced2e199492aa61a3eab163d4c2625c873e95cafd95b80dd2d8732c8e25638a2007acfa6c8f1ff31cc2bc4ca8f4446f51da404335a48c955aaa3a4b57250d7ba29700b

def crc8(s):
    z=0xffffffff
    for i in s:
        z ^= ord(i)
        for j in range(0, 8):
            if z & 1:
                z = (z >> 1) ^ 0xedb88320
            else:
                z = (z >> 1)
    return z

class rsa_aes():
    def __init__(self, s):
        self.stream = s
        self.handshake()

    def handshake(self):
        self.rand192 = os.urandom(24)
        print "rand192=" + hexlify(self.rand192)
        self.make_aes()

    def expand_session_key(self):
        x192=self.rand192*8
        x192=chr(1) + x192[1:]
        return x192
    
    def make_aes(self):
        x192=self.expand_session_key()
        p1=sha1(unhexlify('00000000')+x192).digest()[:20]
        p2=sha1(unhexlify('00000001')+x192).digest()[:12]
        self.aes = AES.new(p1+p2)

    def aes_crypt(self, msg, iv, p=0):
        n=p << 16
        out=[]
        while(msg):
            z=self.aes.encrypt(pack('>IIII', iv, iv, 0, n))
            m=msg[:16]
            msg=msg[16:]
            n=n+1
            out.append(''.join([chr(ord(a) ^ ord(b)) for a,b in zip(m, z)]))
        return ''.join(out)

    def encrypt_session_key(self):
        x192=self.expand_session_key()
        return unhexlify("%0384x" % pow(int(hexlify(x192), 16), 0x10001, login_key))

    def session_setup_packet(self):
        payload=[
            Buf(i=8, d=self.encrypt_session_key()), 
            Dword(i=1, d=0x00002000), 
            Dword(i=3, d=0x00000001)
        ]
        payload=chr(0x42) + pack42.write42().write(payload)
        return unhexlify('160301') + pack(">H", len(payload)) + payload

    def auth_packet(self, cmd):
        return [
            Dword(i=0, d=cmd), 
            Dword(i=2, d=0x00000001), 
            String(i=4, d=skypename), 
            Buf(i=5, d=md5('%s\nskyper\n%s' % (skypename, password)).digest())
        ]

    def second_packet(self, cmd, params):
        payload=[self.auth_packet(cmd), params]
        payload=''.join([pack41.write41().write_list(x, False) for x in payload])
        payload=self.aes_crypt(payload, 0)
        payload=payload + pack("<H", crc8(payload) & 0xffff)

        return unhexlify('170301') + pack(">H", len(payload)) + payload

    def recv_hdr(self):
        b = self.stream.recv(5)
        
        if b[:3] != unhexlify('170301'):
            raise Exception("pkt not starting with 170301: %s" % hexlify(b))

        b=b[3:]
        l=unpack(">H", b)[0]
        return l

    def recv_body(self, l, p):
        b = self.stream.recv(l)
        crc = unpack("<H", b[-2:])[0]
        b = b[:-2]

        acrc = crc8(b) & 0xffff
        acrc = acrc ^ p

        if acrc != crc:
            raise Exception("crc missmatch %x != %x" % (crc, acrc))

        return b

    def recv_packet(self, p):
        b = self.recv_body(self.recv_hdr(), p)
        b = self.aes_crypt(b, 1, p)
        print "=== " + hexlify(b)
        return b

    def execute(self, cmd, params):
        b=self.session_setup_packet() + self.second_packet(cmd, params)
        self.stream.send(b)
        i=0
        while True:
            b = self.recv_packet(i)
            i = i+1
            parser = pack41.read41(b);
            resp = parser.read_list()
            result = getbyid(resp, 1)
            if result:
                return (resp, parser.read_list())

