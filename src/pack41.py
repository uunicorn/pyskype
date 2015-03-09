
from binascii import hexlify, unhexlify
import things
from pack42 import read42

class write41():
    def write_thing(self, l):
        pkt = chr(l.t) + self.write_dword(l.i)
        if l.t == 5:
            return pkt + self.write_list(l.d, False)
        elif l.t == 4:
            return pkt + self.write_dword(len(l.d)) + l.d
        elif l.t == 3:
            return pkt + l.d + '\0'
        elif l.t == 0:
            return pkt + self.write_dword(l.d)
        elif l.t == 1:
            return pkt + l.d
        elif l.t == 2:
            return pkt + l.d
        elif l.t == 6:
            return pkt + self.write_dword(len(l.d)) + ''.join([self.write_dword(x) for x in l.d])
        else:
            raise Exception("Woah! Dont know how to handle type %d" % l.t)

    def write_dword(self, n):
        pkt = ''
        while n > 0x7f:
            pkt += chr((n & 0x7f) | 0x80)
            n >>= 7
        return pkt + chr(n & 0x7f)

    def write_list(self, ls, is42):
        if is42:
            return chr(0x42) + read42.write42().write(ls)
        else:
            return chr(0x41) + self.write_dword(len(ls)) + ''.join([self.write_thing(l) for l in ls])


class read41():
    def __init__(self, bin):
        self.pkt = bin
        self.ptr = 0
        self.size = 0
        self.params = 0

    def eof(self):
        return self.ptr >= len(self.pkt)

    def get(self):
        b = self.pkt[self.ptr]
        self.ptr += 1
        return ord(b)

    def read_dword(self):
        s = 0
        r = 0
        while True:
            b = self.get()
            r += (b & 0x7f) << s
            s += 7
            if b & 0x80 == 0:
                return r

    def read_thing(self):
        t = self.get()
        id = self.read_dword()
        if t == 5:
            return things.List(id, self.read_list())
        elif t == 4:
            l = self.read_dword()
            d = self.pkt[self.ptr:(self.ptr+l)]
            self.ptr += l
            return things.Buf(id, l, d)
        elif t == 3:
            i = self.ptr
            while True:
                if self.get() == 0:
                    return things.String(id, self.pkt[i:self.ptr-1])
        elif t == 0:
            return things.Dword(id, self.read_dword())
        elif t == 1:
            d = self.pkt[self.ptr:(self.ptr+8)]
            self.ptr += 8
            return things.Qword(id, 8, d)
        elif t == 2:
            d = self.pkt[self.ptr:(self.ptr+6)]
            self.ptr += 6
            return things.Sockaddr(id, d)
        elif t == 6:
            l = self.read_dword()
            d = [self.read_dword() for x in range(0, l)]
            return things.Numbers(id, d)
        else:
            raise Exception("Woah! Dont know how to handle type %d" % t)

    def read(self):
        self.size = self.read_dword()
        self.cmd = self.read_dword()
        print "size=%d cmd=%x" % (self.size, self.cmd)
        if self.cmd & 0x2 == 2:
            self.id = self.get() << 8
            self.id += self.get()
        else:
            self.id = 0
        self.params = self.read_list()

    def read_list(self):
        fmt = self.get()
        if fmt == 0x42:
            return read42(self.pkt[self.ptr:]).read()
        elif fmt == 0x41:
            n = self.read_dword()

            r = []
            for i in range(0, n):
                t = self.read_thing()
                r += [t]

            return r
        else:
            raise Exception("Unknown format %x" % fmt)

    
