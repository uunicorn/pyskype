
from binascii import hexlify, unhexlify
from pack41 import read41
import things

skype_pub= 0xb8506aeed8ed30fe1c0e6774874b59206a77329042a49be2403da47d50052441067f87bcd57e6579b83df0bade2beff5b5cd8d87e8b3edac5f57fabccd49695974e2b5e5f0287d6c19ecc31b4504a9f8be25da78fa4ef345f91d339b73cc2d70b3904e11ca570ce9b5dc4b08b3c44b74dc463587ea637ef4456e61462b72042fc2f4ad5510a9850c06dc9a7374412fcadda955bd9800f9754cb3b8cc62d0e98d8282180971055b457c06f351e61164fc5a9de9d83d1d1378964001380b5b99ee4c5c7d50ac2462a4b7ea34fd32d90bd8d4b46410263673f900d1c60470165df9f3cb48016ab8ca45ce6875a71d977915ca8251b50258748dbc37fe332edc2855

def align(depth):
    return "  " * depth

def num2bin(n):
    h = "%x" % n
    if len(h) & 1 == 1:
        h = "0" + h
    return unhexlify(h)

def dump_profile(d, depth=0):
    d = d[4:]
    ciphcert = d[0:0x100]
    rest = d[0x100:]
    clearcert = num2bin(pow(int(ciphcert.encode('hex'), 16),0x10001,skype_pub))
    if clearcert[0] != '\x4b':
        raise Exception("oops")

    clearcert = clearcert[1:]
    while clearcert[0] == '\xbb':
        clearcert = clearcert[1:]

    if clearcert[0] != '\xba':
        raise Exception("oops")

    clearcert = clearcert[1:]

    cert = read41(clearcert).read_list()

    print "%sCert[" % align(depth)
    dump(cert, depth + 1)
    print "%s]" % align(depth)

def dump(ts, depth=0):

    for t in ts:
        if isinstance(t, things.List):
            print "%sList(%s, [" % (align(depth), t.i)
            dump(t.d, depth+1)
            print "%s]" % align(depth)
        elif isinstance(t, things.Buf) and t.i == 1 and False:
            print align(depth) + "NodeInfo: id=%s, 01=%s, private=%s, node=%s, public=%s, rest=%s" % (
               hexlify(t.d[0:8]),
               hexlify(t.d[8:9]),
               sockaddr2str(t.d[9:15]),
               sockaddr2str(t.d[15:21]),
               sockaddr2str(t.d[21:27]),
               hexlify(t.d[27:]),
               )
        elif isinstance(t, things.Buf) and t.i == 11:
            print align(depth) + "Profile: ["
            dump_profile(t.d[4:], depth+1)
            print align(depth) + "]"
        else:
            print align(depth) + repr(t)

def dump_pkt(pkt):
    print "Packet: size=%d cmd=%x id=%x" % (pkt.size, pkt.cmd, pkt.id)
    dump(pkt.params)

