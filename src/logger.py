
import socket, ssl, re, threading, uuid, Queue

from binascii import hexlify, unhexlify, crc32, b2a_base64
from hashlib import sha1
from lxml import etree
from StringIO import StringIO
from funnydigest import funnydigest

from cred import *
from login import uic

epid="cabba291-a68d-9370-3a70-26009dc4fb0e" # TODO make uniq?

registration=""

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

class Connection():
    def connect(self, host, port):
        print "Connecting to %s:%d" % (host, port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.ssl_sock = ssl.wrap_socket(s)
        self.ssl_sock.connect((host, port))
        self.sock_file = self.ssl_sock.makefile()

        self.cnt = 0
        self.queue = Queue.Queue(-1)
        self.pending_requests = { }
        
        self.sender = threading.Thread(target=self.sender_loop)
        self.sender.setDaemon(True)
        self.sender.start()

        self.receiver = threading.Thread(target=self.receiver_loop)
        self.receiver.setDaemon(True)
        self.receiver.start()

        self.start_handshake()

    def shutdown(self):
        self.ssl_sock.close()
        self.send(None, None, None, None)

    def send(self, cmd, url, body, callback=None):
        if callback == None:
            callback = self.nop
        self.queue.put((cmd, url, body, callback))

    def sender_loop(self):
        global cnt
        while True:
            try:
                cmd, url, body, callback = self.queue.get(True, 500)
                if cmd == None:
                    break
                self.cnt = self.cnt + 1
                self.pending_requests[self.cnt] = callback
                p = "%s %d %s %d\r\n%s" % (cmd, self.cnt, url, len(body), body)
                print ">>>>>>> %d pending requests" % len(self.pending_requests)
                print p
                self.ssl_sock.send(p)
            except Queue.Empty:
                self.send("PNG", "CON", reg())

    def handle(self, cmd, cnt, url, hdr, body):
        print "inbound " + cmd

    def receiver_loop(self):
        global registration

        while True:
            l = self.sock_file.readline()
            print "<<<<<<<"
            print l
            cmd, cnt, url, bsz = l.split()
            cnt = int(cnt)
            body = self.sock_file.read(int(bsz))
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

            if cmd == "XFR":
                self.handle_XFR(cmd, url, hdr, body)
                break

            if cnt:
                callback = self.pending_requests[cnt]
                callback(cmd, url, hdr, body)
                del self.pending_requests[cnt]
            else:
                self.handle(cmd, cnt, url, hdr, body)

    def nop(self, cmd, url, hdr, body):
        print "ignoring reply " + cmd

    def handle_XFR(self, cmd, url, hdr, body):
        self.shutdown()

        root = etree.parse(StringIO(body))
        target = root.xpath("/xfr/target")[0].text
        target = target.split(':')
        self.connect(target[0], int(target[1]))

    def handle_CNT_reply(self, cmd, url, hdr, body):
        assert cmd == "CNT"

        root=etree.parse(StringIO(body))
        nonce=root.xpath("/connect-response/nonce")[0].text

        self.send("ATH", "CON\USER", "\r\n<user><uic>" + uic(nonce, "WS-SecureConversationSESSION KEY TOKEN") + "</uic><id>" + skypename + "</id></user>\r\n", self.handle_ATH_reply);

    def handle_ATH_reply(self, cmd, url, hdr, body):
        assert cmd == "ATH"

        self.send("BND", "CON\MSGR", "\r\n<msgr><ver>2</ver><altVersions><ver>1</ver></altVersions><client><name>Skype</name><ver>2/4.3.0.37/172</ver></client><epid>" + epid + "</epid></msgr>\r\n", self.handle_BND_reply)


    def handle_BND_reply(self, cmd, url, hdr, body):
        assert cmd == "BND"

        root=etree.parse(StringIO(body))
        nonce=root.xpath("/msgr-response/nonce")[0].text

        rsp=funnydigest(nonce)

        self.send("PUT", "MSGR\CHALLENGE", reg() + "<challenge><appId>PROD0090YUAUV{2B</appId><response>" + rsp + "</response></challenge>\r\n")

        self.send("PUT", "MSGR\PRESENCE", reg() + routing("8:" + skypename) + reliability() + publication())

        self.send("PUT", "MSGR\SUBSCRIPTIONS", reg() + "<subscribe><presence><buddies><all /></buddies></presence><messaging><im /><conversations /></messaging></subscribe>")

        self.send("GET", "MSGR\RECENTCONVERSATIONS", reg() + "<recentconversations><pagesize>100</pagesize></recentconversations>")

    def start_handshake(self):
        self.send("CNT", "CON", "\r\n<connect><ver>2</ver><agent><os>Linux</os><osVer>Linux 3.11.0-12-gene</osVer><proc>2 1800 I-586-6-15-13 Intel Core2</proc><lcid>en-US</lcid><country>nz</country></agent></connect>\r\n", self.handle_CNT_reply)

    def msgr(self, body):
        self.send("SDG", "MSGR", reg() + body)

connection = Connection()
connection.connect('s.gateway.messenger.live.com', 443)

# to send a message:
# connection.msgr(routing("8:" + skypename) + reliability() + messaging_rich("Oh, hi!"))

# TODO: handle OUT/reconnect

# TODO: send ACKs:
# ACK 0 MSGR 436
# Ack-Id: 0000014BDE39B23E
# Registration: ...

# TODO: remember recentconversations state and restore on reconnect
