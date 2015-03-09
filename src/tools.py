import re, os, socket
from binascii import *
from hashlib import *
from Crypto.Cipher import AES
from struct import pack, unpack
from things import *
from dh_rc4 import transport_stream
from rsa_aes import *
import rsa_keygen

from cred import *

search_host='91.190.216.123'
search_port=12350

login_host='91.190.216.17'
login_port=33033

aux_host='91.190.218.125'
aux_port=12350


def gdb2hex(dump):
    return "".join(map(lambda x: re.sub('(\t|  *)0x', '', re.sub(r'.*:', r'', x)), dump.split("\n")))

def tcpdump2hex(dump):
    return "".join([re.sub(' ', '', re.sub(r'.*:  (.*)  .*', r'\1', x)) for x in dump.split("\n")])

def connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def search_req():
    s=rsa_aes(transport_stream(connect(search_host, search_port)))
    search=[
        List(i=32, d=[
            Dword(i=33, d=0x00000000), 
            Dword(i=34, d=0x00000005), 
            String(i=35, d='test')
        ]), 
        List(i=32, d=[
            Dword(i=33, d=0x00000011), 
            Dword(i=34, d=0x00000000), 
            Dword(i=35, d=0x00000000)
        ]), 
        List(i=32, d=[
            Dword(i=33, d=0x00000001), 
            Dword(i=34, d=0x00000008), 
            String(i=35, d='test')
        ]), 
        List(i=32, d=[
            Dword(i=33, d=0x00000011),
            Dword(i=34, d=0x00000000),
            Dword(i=35, d=0x00000000)
        ]),
        List(i=32, d=[
            Dword(i=33, d=0x00000002), 
            Dword(i=34, d=0x00000009), 
            String(i=35, d='test')
        ]), 
        String(i=38, d='skype'), 
        Dword(i=36, d=0x00000000),
        String(i=4, d=skypename), 
        String(i=13, d='2/4.3.0.37/172'), 
        Dword(i=14, d=0xb630882c)
    ]
    print s.execute(0x00004278, search)

search_req()
