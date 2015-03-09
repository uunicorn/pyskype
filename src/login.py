import re, os, socket
from binascii import *
from things import *
from dh_rc4 import transport_stream
from rsa_aes import *
import rsa_keygen
from dump import dump_profile

login_host='91.190.216.17'
login_port=33033

def connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def login_req():
    e, n, d = rsa_keygen.make_rsa_keypair()
    print (e, n, d)
    s=rsa_aes(transport_stream(connect(login_host, login_port)))
    pub_key=unhexlify("%0256x" % n)
    login=[
        Buf(i=33, d=pub_key), 
        Qword(i=49, d=unhexlify('2c097aeacabba291')), # TODO: compute hostkey1
        Numbers(i=51, d=[0xcabba291, 0x9370a68d, 0xafcc1c6e, 0xe16fa568, 0xcabba291]), # TODO: compute hostkey2
        String(i=13, d='2/4.3.0.37/172'), 
        Dword(i=14, d=0x7f000001)
    ]
    response, params = r = s.execute(0x000013a3, login)
    print response
    cert = getbyid(params, 36)[0].d
    dump_profile(cert)
    return (e, n, d, cert)

#print login_req()

