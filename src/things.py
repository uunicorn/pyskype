
from binascii import hexlify, unhexlify

def sockaddr2str(s):
    o = map(ord, s[0:4])
    return "%u.%u.%u.%u:%u" % (o[0], o[1], o[2], o[3], (ord(s[4]) << 8) | ord(s[5]))

class Dword():
    def __init__(self, i, d):
        self.t = 0
        self.i = i
        self.d = d

    def __repr__(self):
        return "Dword(i=%d, d=0x%08x)" % (self.i, self.d)

class Sockaddr():
    def __init__(self, i, d=""):
        self.t = 2
        self.i = i
        self.d = d

    def __repr__(self):
        return "Sockaddr(i=%d, d=%s)" % (self.i, repr(sockaddr2str(self.d)))

class Qword():
    def __init__(self, i, l=8, d = ""):
        self.t = 1
        self.i = i
        self.l = l
        self.d = d

    def __repr__(self):
        return "Qword(i=%d, d=unhexlify('%s'))" % (self.i, hexlify(self.d))

class Buf():
    def __init__(self, i, l=0, d = ""):
        self.t = 4
        self.i = i
        self.l = l
        self.d = d

    def __repr__(self):
        return "Buf(i=%d, d=unhexlify('%s'))" % (self.i, hexlify(self.d))

class List():
    def __init__(self, i, d):
        self.t = 5
        self.i = i
        self.d = d

    def __repr__(self):
        return "List(i=%d, d=%s)" % (self.i, repr(self.d))

class String():
    def __init__(self, i, d):
        self.t = 3
        self.i = i
        self.d = d

    def __repr__(self):
        return "String(i=%d, d=%s)" % (self.i, repr(self.d))

class Numbers():
    def __init__(self, i, d):
        self.t = 6
        self.i = i
        self.d = d

    def __repr__(self):
        return "Numbers(i=%d, d=%s)" % (self.i, repr(self.d))

def getbyid(l, i):
    return filter(lambda x: x.i == i, l)

