
import socket, ssl, re, threading, uuid, Queue

from binascii import hexlify, unhexlify, crc32, b2a_base64
from hashlib import sha1
from lxml import etree
from StringIO import StringIO
from funnydigest import funnydigest

from cred import *
from login import login_req

epid="cabba291-a68d-9370-3a70-26009dc4fb0e" # TODO make uniq?

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = ssl.wrap_socket(s)

registration=""

e, n, d, cert = login_req()

def encrypt(m):
    global e, n
    return pow(m, e, n)

def decrypt(c):
    global d, n
    return pow(c, d, n)

def n2m(n):
    return unhexlify("%0256x" % n)

def m2n(m):
    return int(hexlify(m), 16)

def uic_pkt(nonce, salt):
    msg=sha1(cert + salt).digest() + salt + nonce
    msg=msg+sha1(msg).digest()
    pad=0x80-3-len(msg) # pad the packet with 0xbb up to 0x80 bytes
    pkt=chr(0x4b) + (chr(0xbb) * pad) + chr(0xba) + msg + chr(0xbc)
    return pkt

def uic(nonce, salt):
    uic=unhexlify('00000104') + cert + n2m(decrypt(m2n(uic_pkt(nonce, salt))))
    return b2a_base64(uic)


# TODO connect to 'multiplexer' host?
#remote=('s.gateway.messenger.live.com', 443)
remote=('BAYMSGR2011110.gateway.messenger.live.com', 443)

ssl_sock.connect(remote)
sock_file=ssl_sock.makefile()


crlf='\r\n'

def entity(cmd, hdr, body=''):
    if len(body) > 0:
        hdr['Content-Length'] = str(len(body))
    return cmd + crlf + "".join("%s: %s\r\n" % i for i in hdr.iteritems()) + crlf + body

def reg():
    global registration
    return "Registration: " + registration + "\r\n\r\n"

def messaging_plain(body, hdr={}):
    defaults = {
        'Content-Type': 'Text/plain; charset=UTF-8',
        'Message-Type': 'Text',
        'Client-Message-ID': str(uuid.uuid1().int>>64),
        'IM-Display-Name': 'dummy'
    }
    defaults.update(hdr)
    return entity("Messaging: 2.0", defaults, body)

def messaging_rich(body, hdr={}):
    defaults = {
        'Content-Type': 'application/user+xml',
        'Message-Type': 'RichText',
        'Client-Message-ID': str(uuid.uuid1().int>>64),
        'IM-Display-Name': 'dummy'
    }
    defaults.update(hdr)
    return entity("Messaging: 2.0", defaults, body)

def reliability():
    return "Reliability: 1.0\r\n\r\n"

def routing(to, hdr={}):
    defaults = {
        'To': to, 
        'From': "8:" + skypename + ";epid={" + epid + "}" 
    }
    defaults.update(hdr)
    return entity("Routing: 1.0", defaults)

def publication(hdr={}):
    defaults = {
        'Uri': '/user',
        'Content-Type': 'application/user+xml'
    }
    defaults.update(hdr)
    body='<user><sep n="PE" epid="{' + epid + '}"><VER>2/4.3.0.37/172</VER><TYP>14</TYP><Capabilities>0:0</Capabilities></sep><s n="IM"><Status>NLN</Status></s><sep n="IM" epid="{' + epid + '}"><Capabilities>0:4194560</Capabilities></sep><sep n="PD" epid="{' + epid + '}"><EpName>ubuntu</EpName><ClientType>14</ClientType></sep><s n="SKP"><Mood/><Skypename>' + skypename + '</Skypename></s><sep n="SKP" epid="{' + epid + '}"><NodeInfo>x8b24a10d59cbd00e01c0a80137d4126fdd4d8f9c4cb6308989d4120801</NodeInfo><Version>24</Version><Seamless>true</Seamless></sep></user>'
    return entity("Publication: 1.0", defaults, body)

def nop(cmd, url, hdr, body):
    print "ignoring reply " + cmd

class Sender(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.cnt = 0
        self.queue = Queue.Queue(-1)
        self.pending_requests = { }
        self.next_timeout = 500
        self.start()

    def send(self, cmd, url, body, callback=nop):
        self.queue.put((cmd, url, body, callback))

    def run(self):
        global cnt
        while True:
            try:
                cmd, url, body, callback = self.queue.get(True, self.next_timeout)
                self.cnt = self.cnt + 1
                self.pending_requests[self.cnt] = callback
                p = "%s %d %s %d\r\n%s" % (cmd, self.cnt, url, len(body), body)
                print ">>>>>>> %d pending requests" % len(self.pending_requests)
                print p
                ssl_sock.send(p)
            except Queue.Empty:
                self.send("PNG", "CON", reg())

sender = Sender()

class Receiver(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.start()

    def handle(self, cmd, cnt, url, hdr, body):
        print "inbound " + cmd

    def run(self):
        global registration

        while True:
            l = sock_file.readline()
            print "<<<<<<<"
            print l
            cmd, cnt, url, bsz = l.split()
            cnt = int(cnt)
            body = sock_file.read(int(bsz))
            print body
            if body[:2] == "\r\n":
                hdr = dict()
                body = body[2:]
            else:
                cut_here = body.find("\r\n\r\n")
                hdr = body[:cut_here]
                body = body[cut_here+4:]
                hdr = hdr.split("\r\n")
                if hdr[0] == "":
                    hdr = hdr[1:]
                hdr = dict(x.split(": ") for x in hdr)

            if "Set-Registration" in hdr:
                registration=hdr["Set-Registration"]

            if cnt:
                callback = sender.pending_requests[cnt]
                callback(cmd, url, hdr, body)
                del sender.pending_requests[cnt]
            else:
                self.handle(cmd, cnt, url, hdr, body)

def handle_CNT_reply(cmd, url, hdr, body):
    assert cmd == "CNT"

    root=etree.parse(StringIO(body))
    nonce=root.xpath("/connect-response/nonce")[0].text

    sender.send("ATH", "CON\USER", "\r\n<user><uic>" + uic(nonce, "WS-SecureConversationSESSION KEY TOKEN") + "</uic><id>" + skypename + "</id></user>\r\n", handle_ATH_reply);

def handle_ATH_reply(cmd, url, hdr, body):
    assert cmd == "ATH"

    sender.send("BND", "CON\MSGR", "\r\n<msgr><ver>2</ver><altVersions><ver>1</ver></altVersions><client><name>Skype</name><ver>2/4.3.0.37/172</ver></client><epid>" + epid + "</epid></msgr>\r\n", handle_BND_reply)


def handle_BND_reply(cmd, url, hdr, body):
    assert cmd == "BND"

    root=etree.parse(StringIO(body))
    nonce=root.xpath("/msgr-response/nonce")[0].text

    rsp=funnydigest(nonce)

    sender.send("PUT", "MSGR\CHALLENGE", reg() + "<challenge><appId>PROD0090YUAUV{2B</appId><response>" + rsp + "</response></challenge>\r\n")

    sender.send("PUT", "MSGR\PRESENCE", reg() + routing("8:" + skypename) + reliability() + publication())

    sender.send("PUT", "MSGR\SUBSCRIPTIONS", reg() + "<subscribe><presence><buddies><all /></buddies></presence><messaging><im /><conversations /></messaging></subscribe>")

    sender.send("GET", "MSGR\RECENTCONVERSATIONS", reg() + "<recentconversations><pagesize>100</pagesize></recentconversations>")

def start_handshake():
    sender.send("CNT", "CON", "\r\n<connect><ver>2</ver><agent><os>Linux</os><osVer>Linux 3.11.0-12-gene</osVer><proc>2 1800 I-586-6-15-13 Intel Core2</proc><lcid>en-US</lcid><country>nz</country></agent></connect>\r\n", handle_CNT_reply)

def msgr(body):
    sender.send("SDG", "MSGR", reg() + body)

receiver = Receiver()

start_handshake()

# to send a message:
# msgr(routing("8:" + skypename) + reliability() + messaging_rich("Oh, hi!"))

# TODO: handle:
# XFR 3 CON 204
#
#<xfr><target>BAYMSGR2011012.gateway.messenger.live.com:443</target><flags>S</flags><state>VmVyc2lvbjogMQ0KWGZyQ291bnQ6IDENClhmclNlbnRVVENUaW1lOiA2MzU2MTE4OTE5MzM0MDMwODANCg==</state><wait>0</wait></xfr>

# TODO: handle OUT/reconnect

# TODO: send ACKs:
# ACK 0 MSGR 436
# Ack-Id: 0000014BDE39B23E
# Registration: ...

# TODO: remember recentconversations state and restore on reconnect
