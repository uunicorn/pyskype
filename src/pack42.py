
from sys import argv
from binascii import hexlify, unhexlify
import things


typeranges=[0,0x2A3,0x37C,0x67C,0x6A3,0x6AE,0x0A84,0x0B74,0x0DAD,0x0F5D,0x0FB2,0x0FD4,0x0FFF,0x1000]

idranges=[0,0x123,0x266,0x2B4,0x8A2,0x9F5,0x0CFC,0x0F70,0x0FFF,0x1000]
iddict=[7,2,1,idranges]

binranges=[0,0x14D,0x34C,0x42B,0x4A3,0x6CA,0x953,0x9C6,0x0A6C,0x0ABB,0x0BAE,0x0C43,0x0C9B,0x0CDD,0x0D31,0x0D93,0x0DB5,0x1000]
bindict=[16,1,0,binranges]

strings=[
	"\0",
	"tdmhkpcgwbzfvjq",
	"eaiouy",
	"nrlsx",
	"0216345789",
	"SMTBRLNPKCDHGJWFVZXQ",
	"AEIOUY",
	" ",
	"\x82\x99\xB8\xB3\xA9\x81\xBC\x9C\x85\x95\xA1\x9B\xA8\x84\xB0\x90\x80\xB6\x94\xA4\x91\xBA\x9E\x9A\xA0\xB5\xBD\xBE\xA7\x9D\x97\xA5\x9F\xAA\xB1\x83\x8C\x93\xB2\x98\xA6\xA2\xBB\x88\xAD\x96\x8F\xB4\xA3\x92\xBF\x87\xB7\x8B\x8D\xB9\x89\x8A\x8E\xAE\x86\xAC\xAB\xAF",
	"\xD7\xC3\xD0\xC5\xE5\xC4\xE3\xD1\xE6\xE7\xEC\xE4\xE8\xEF\xE9\xD9\xD8\xEB\xEA\xE2\xC2\xE0\xED\xC6\xDB\xE1\xCE\xCF\xC0\xC1\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xD2\xD3\xD4\xD5\xD6\xDA\xDC\xDD\xDE\xDF\xEE\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
	"\x2E\x2D\x2F\x5F\x21\x2B\x2C\x29\x3A\x28\x2A\x3F\x0D\x0A\x27\x26\x22\x3D\x3B\x7E\x40\x3E\x3C\x7C\x5E\x5D\x5B\x5C\x23\x60\x24\x25\x7B\x7D\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0B\x0C\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F"
]

letter_group=[
     0,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
    10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
     7,10,10,10,10,10,10,10,10,10,10,10,10,10,10,10,
     4, 4, 4, 4, 4, 4, 4, 4, 4, 4,10,10,10,10,10,10,
    10, 6, 5, 5, 5, 6, 5, 5, 5, 6, 5, 5, 5, 5, 5, 6,
     5, 5, 5, 5, 5, 6, 5, 5, 5, 6, 5,10,10,10,10,10,
    10, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 3, 1, 3, 2,
     1, 1, 3, 3, 1, 2, 1, 1, 3, 2, 1,10,10,10,10,10,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
     9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9
]

letter_index=[
    0,34,35,36,37,38,39,40,41,42,13,43,44,12,45,46,
    47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,
     0, 4,16,28,30,31,15,14, 9, 7,10, 5, 6, 1, 0, 2,
     0, 2, 1, 4, 5, 6, 3, 7, 8, 9, 8,18,22,17,21,11,
    20, 0, 3, 9,10, 1,15,12,11, 2,13, 8, 5, 1, 6, 3,
     7,19, 4, 0, 2, 4,16,14,18, 5,17,26,27,25,24, 3,
    29, 1, 9, 6, 1, 0,11, 7, 3, 2,13, 4, 2, 2, 0, 3,
     5,14, 1, 3, 0, 4,12, 8, 4, 5,10,32,23,33,19,63,
    16, 5, 0,35,13, 8,60,51,43,56,57,53,36,54,58,46,
    15,20,49,37,18, 9,45,30,39, 1,23,11, 7,29,22,32,
    24,10,41,48,19,31,40,28,12, 4,33,62,61,44,59,63,
    14,34,38, 3,47,25,17,52, 2,55,21,42, 6,26,27,50,
    28,29,20, 1, 5, 3,23,30,31,32,33,34,35,36,26,27,
     2, 7,37,38,39,40,41, 0,16,15,42,24,43,44,45,46,
    21,25,19, 6,11, 4, 8, 9,12,14,18,17,10,22,47,13,
    48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63
]

letter_ranges=[
    [0,0x1000],
    [0,0x636,0x9C8,0x0AED,0x0BE5,0x0CA5,0x0F0E,0x0F7C,0x0F83,0x0F8A,0x0FC2,0x1000],
    [0,0x229,0x3E3,0x550,0x6B9,0x816,0x969,0x0AB9,0x0BB7,0x0CAE,0x0D8A,0x0E42,0x0EF7,0x0F87,0x0FF1,0x1000],
    [0,0x1E1,0x470,0x0C5C,0x0E79,0x0E88,0x0E8F,0x0E96,0x0F57,0x0F5E,0x0F87,0x1000],
    [0,0x452,0x899,0x0B87,0x0E15,0x0F61,0x1000],
    [0,0x21D,0x66A,0x87E,0x0E9F,0x0EAF,0x0EB6,0x0EBD,0x0F97,0x0F9E,0x0FBF,0x1000],
    [0,0x4B8,0x8CB,0x0C89,0x0FC1,0x1000],
    [0,0x3A9,0x76F,0x0CBA,0x0E7F,0x0E8E,0x0E95,0x0E9C,0x0F85,0x0F8C,0x0FB4,0x1000],
    [0,0x241,0x42A,0x5E2,0x775,0x901,0x0A88,0x0BFD,0x0D58,0x0EB2,0x1000],
    [0,0x1D4,0x1DB,0x1E2,0x1E9,0x0E93,0x0E9A,0x0EA1,0x0F31,0x0F38,0x0F3F,0x1000],
    [0,0x1A0,0x2FA,0x420,0x539,0x63B,0x739,0x836,0x928,0x0A07,0x0AE6,0x0BB7,0x0C86,0x0D43,0x0DF2,0x0EA1,0x0F2F,0x0F97,0x0FD8,0x0FF0,0x1000],
    [0,0x0AB,0x1E9,0x0B06,0x0C26,0x0C2D,0x0D68,0x0F05,0x0F4B,0x0F52,0x0FBD,0x1000],
    [0,0x5C8,0x8DA,0x0BBD,0x0E2F,0x0F23,0x1000],
    [0,0x12E,0x36D,0x478,0x898,0x89F,0x0D91,0x0EC5,0x0F92,0x0F99,0x0FA9,0x1000],
    [0,0x1000],
    [0,0x7,0x3EA,0x586,0x6C7,0x847,0x0D5F,0x0E37,0x0EC9,0x0ED0,0x0F5F,0x1000],
    [0,0x0EF,0x1A5,0x242,0x2D4,0x366,0x3EE,0x46A,0x4DA,0x54A,0x5B3,0x619,0x67D,0x6D6,0x72D,0x77D,0x7CC,0x819,0x862,0x8AA,0x8F0,0x935,0x978,0x9BA,0x9F9,0x0A38,0x0A76,0x0AB3,0x0AF0,0x0B2C,0x0B63,0x0B99,0x0BCD,0x0C01,0x0C33,0x0C65,0x0C94,0x0CC3,0x0CF2,0x0D1E,0x0D49,0x0D73,0x0D9B,0x0DC2,0x0DE8,0x0E0D,0x0E31,0x0E53,0x0E73,0x0E93,0x0EB1,0x0ECF,0x0EED,0x0F0B,0x0F28,0x0F44,0x0F5F,0x0F79,0x0F91,0x0FA6,0x0FBB,0x0FD0,0x0FE2,0x0FF1,0x1000],
    [0,0x14D,0x29D,0x374,0x526,0x52D,0x53A,0x541,0x649,0x929,0x0FB1,0x1000],
    [0,0x233,0x561,0x755,0x940,0x0A05,0x0ABD,0x0B48,0x0BD0,0x0C40,0x0C8A,0x0CCB,0x0D0B,0x0D47,0x0D7F,0x0DB2,0x0DE2,0x0E05,0x0E19,0x0E2D,0x0E40,0x0E50,0x0E5C,0x0E66,0x0E70,0x0E7A,0x0E84,0x0E8E,0x0E98,0x0EA2,0x0EAC,0x0EB6,0x0EC0,0x0ECA,0x0ED4,0x0EDE,0x0EE8,0x0EF2,0x0EFC,0x0F06,0x0F10,0x0F1A,0x0F24,0x0F2E,0x0F38,0x0F42,0x0F4C,0x0F56,0x0F60,0x0F6A,0x0F74,0x0F7E,0x0F88,0x0F92,0x0F9C,0x0FA6,0x0FB0,0x0FBA,0x0FC4,0x0FCE,0x0FD8,0x0FE2,0x0FEC,0x0FF6,0x1000],
    [0,0x7,0x0E,0x15,0x1C,0x23,0x2A,0x31,0x38,0x0FF2,0x0FF9,0x1000],
    [0,0x32F,0x712,0x82B,0x904,0x9C3,0x0A78,0x0B27,0x0BC0,0x0C42,0x0C9A,0x0CEA,0x0D36,0x0D7E,0x0DC5,0x0DEE,0x0E06,0x0E1B,0x0E30,0x0E3C,0x0E48,0x0E52,0x0E5C,0x0E66,0x0E70,0x0E7A,0x0E84,0x0E8E,0x0E98,0x0EA2,0x0EAC,0x0EB6,0x0EC0,0x0ECA,0x0ED4,0x0EDE,0x0EE8,0x0EF2,0x0EFC,0x0F06,0x0F10,0x0F1A,0x0F24,0x0F2E,0x0F38,0x0F42,0x0F4C,0x0F56,0x0F60,0x0F6A,0x0F74,0x0F7E,0x0F88,0x0F92,0x0F9C,0x0FA6,0x0FB0,0x0FBA,0x0FC4,0x0FCE,0x0FD8,0x0FE2,0x0FEC,0x0FF6,0x1000],
    [0,0x15E,0x41C,0x4CE,0x59C,0x8C0,0x985,0x9B0,0x0B2C,0x0B33,0x0B58,0x1000]
]


class StackLevel():
    def __init__(self):
        self.typeOrder=[0,4,3,5,2,6,1]
        self.ids=[0]*16
        self.types=[0]*16
        self.things=0

    def rotate(self, i):
        t = self.typeOrder
        self.typeOrder=[t[i]] + t[0:i] + t[(i+1):]

class write42():
    def __init__(self):
        self.stack = [StackLevel(), StackLevel(), StackLevel()]
        self.pkt = ''
        self.raw_data = ''
        self.width = 0x80000000
        self.left = 0
        self.repeat = 0
        self.lastbyte = 0
        self.skip_first = True
    
    def write(self, ls):
        self.write_list(ls, 0)
        self.flush()
        return self.pkt + self.raw_data

    def write_buf(self, b):
        self.write_dword(bindict, len(b))
        self.raw_data += b

    def write_string(self, s):
        g = 0
        s = s + '\0'
        for c in s:
            next_g = letter_group[ord(c)]
            self.write_decision(letter_ranges[g*2+1], next_g)
            g = next_g
            if letter_ranges[g*2][1] != 0x1000:
                self.write_decision(letter_ranges[g*2], letter_index[ord(c)])

    def write_list(self, ls, depth):
        d = min(depth, 2)
        stack = self.stack[d]

        thingcnt = 0
        if d > 0 and stack.things > 0:
            for l in ls:
                if thingcnt >= stack.things:
                    break
                if stack.types[thingcnt] != l.t:
                    break
                if stack.ids[thingcnt] != l.i:
                    break

                thingcnt += 1

            self.write_dword(iddict, thingcnt)

        stack.things = 0
        for l in ls:
            if stack.things >= thingcnt:
                s=stack.typeOrder.index(l.t)
                if s != 0:
                    stack.rotate(s)
                    self.write_decision(typeranges, s+6)
                    self.write_dword(iddict, l.i)
                else:
                    if l.i < 5:
                        self.write_decision(typeranges, l.i + 1)
                    else:
                        self.write_decision(typeranges, 6)
                        self.write_dword(iddict, l.i - 5)

            if stack.things < 16:
                stack.types[stack.things] = l.t
                stack.ids[stack.things] = l.i
                stack.things += 1

            if(l.t == 0):
                self.write_dword(bindict, l.d)
            elif(l.t == 3):
                self.write_string(l.d)
            elif(l.t == 4):
                self.write_buf(l.d)
            elif(l.t == 5):
                self.write_list(l.d, depth + 1)
            else:
                raise Exception("Woah! Dont know how to handle type %d" % l.t)

        self.write_decision(typeranges, 0)
            

    def write_decision(self, ranges, i):
        self.sync()
        w = self.width >> 12
        l, r = ranges[i], ranges[i+1]
        if r == 0x1000:
            self.width -= w*l
        else:
            self.width = w*(r - l)
        self.left += w*l


    def write_bits(self, d, bits):
        self.sync()
        l = d & ( (1 << bits) - 1 )
        r = l + 1
        w = self.width >> bits
        if (r >> bits) == 0:
            self.width = w*(r - l)
        else:
            self.width -= w*l
        self.left += w*l


    def write_dword(self, d, n):
        for b in range(0, 33):
            if n < (1 << b):
                break

        if b > d[1]:
            if b >= d[0]:
                self.write_decision(d[3], d[0] + d[2])
                self.write_dword(d, b - d[0])
            else:
                self.write_decision(d[3], b + d[2])
            
            i=b-1
            while(i):
                nb = min(16, i)
                self.write_bits(n, nb)
                n >>= nb
                i -= nb
        else:
            self.write_decision(d[3], n)

    def add_byte(self, b):
        self.pkt += chr(b & 0xff)

    def sync(self):
        while self.width <= 0x800000:
            if self.left >= 0x7f800000:
                if self.left <= 0x7fffffff:
                    self.repeat += 1
                else:
                    self.add_byte(self.lastbyte + 1)
                    for i in range(0, self.repeat):
                        add_byte(0)
                    self.repeat = 0
                    self.lastbyte = self.left >> 23
            else:
                if self.skip_first:
                    self.skip_first = False
                else:
                    self.add_byte(self.lastbyte)
                for i in range(0, self.repeat):
                    self.add_byte(0xff)
                self.repeat = 0
                self.lastbyte = self.left >> 23
            self.width <<= 8
            self.left = (self.left & 0x7fffff) << 8

    def flush(self):
        self.width >>= 1
        self.left += self.width
        self.sync()
        v1 = self.left >> 23
        if v1 <= 0xff:
            if self.skip_first:
                self.skip_first = False
            else:
                self.add_byte(self.lastbyte)
            for i in range(0, self.repeat):
                self.add_byte(0xff)
            self.repeat = 0
            self.add_byte(v1)
        else:
            add_byte(self.lastbyte + 1)
            for i in range(0, self.repeat):
                self.add_byte(0)
            self.repeat = 0
            self.add_byte(v1)

    def report(self, s=""):
        print "%s[%08x/%08x]" % (s, self.left, self.width)

class read42():
    def __init__(self, bin):
        self.pkt = bin
        self.ptr = 0
        self.stack = [StackLevel(), StackLevel(), StackLevel()]

    def read(self):
        self.nextByte = self.get()
        self.left = self.nextByte >> 1
        self.width = 128

        l = self.read_list(0)
        self.width >>= 1
        self.readup()
        self.ptr -= 3

        self.scanres(l)
        return l

    def get(self):
        if self.ptr < len(self.pkt):
            v = self.pkt[self.ptr]
            self.ptr += 1
            r = ord(v)
            return r
        else:
            self.ptr += 1
            return 0

    def report(self, s=""):
        print "%s[%08x/%08x]" % (s, self.left, self.width)

    def readup(self):
        while self.width <= 0x800000:
            self.left = ((self.left << 1) | (self.nextByte & 1)) << 7
            self.nextByte = self.get()
            self.left |= self.nextByte >> 1
            self.width <<= 8

    def lookup(self, table):
        self.readup()
        w = self.width >> 12
        l = self.left / w
        if l > 0xfff:
            l = 0xfff
        for i in range(1, len(table)):
            if table[i] > l:
                self.left -= w*table[i-1]
                if table[i] == 0x1000:
                    self.width -= w*table[i-1]
                else:
                    self.width = w*(table[i]-table[i-1])
                return i-1
        
        raise Exception("oopsies, lookup failed w=%x, l=%x, table=%x" % (w, l, table[1]))

    def read_bits(self, n):
        self.readup()
        v4 = self.width >> n
        r = self.left / v4
        self.left -= v4 * r
        if((r + 1) >> n):
            self.width -= v4*r
        else:
            self.width = v4
        return r


    def read_dword(self, d):
        r = self.lookup(d[3])

        if r >= (1 << d[1]):
            v6 = r - d[2]

            if v6 >= d[0]:
                v6 += self.read_dword(d) #TODO: prevent recursion

            v11 = v6 - 1
            v10 = 0
            v9 = 1 << v11
            while v10 < v11:
                b = min(v11 - v10, 16)
                v9 += self.read_bits(b) << v10
                v10 += b

            return v9

        return r

    def read_numbers(self):
        n = self.read_dword(bindict)
        r=[]
        for i in range(0, n):
            r += [self.read_dword(bindict)]

        return r

    def read_string(self):
        s = ''
        g = 0
        while True:
            g = self.lookup(letter_ranges[g*2+1])
            l = 0
            if(letter_ranges[g*2][1] != 0x1000):
                l = self.lookup(letter_ranges[g*2])
            c = strings[g][l]
            if c == '\0':
                return s
            s += c

    def read_list(self, depth):
        d = min(depth, 2)
        stack = self.stack[d]

        r = []
        thingcnt = 0
        if d > 0 and stack.things > 0:
            thingcnt = self.read_dword(iddict)

        stack.things = 0
        while True:
            if thingcnt > 0:
                t = stack.types[stack.things]
                id = stack.ids[stack.things]
                thingcnt -= 1
                x = stack.typeOrder.index(t)
                stack.rotate(x)
            else:
                s = self.lookup(typeranges)
                if s == 0:
                    return r
                if s > 6:
                    stack.rotate(s-6)
                    id = self.read_dword(iddict)
                else:
                    if s == 6:
                        id = self.read_dword(iddict) + 5
                    else:
                        id = s - 1

                t = stack.typeOrder[0]

            if stack.things < 16:
                stack.types[stack.things] = t
                stack.ids[stack.things] = id
                stack.things += 1
            
            v = None
            if(t == 0):
                v = things.Dword(id, self.read_dword(bindict))
            elif(t == 1):
                v = things.Qword(id, self.read_dword(bindict))
            elif(t == 2):
                v = things.Sockaddr(id)
            elif(t == 3):
                v = things.String(id, self.read_string())
            elif(t == 4):
                v = things.Buf(id, self.read_dword(bindict))
            elif(t == 5):
                v = things.List(id, self.read_list(depth+1))
            elif(t == 6):
                v = things.Numbers(id, self.read_numbers())
            else:
                raise Exception("Woah! Dont know how to handle type %d" % t)

            r += [v]

    def scanres(self, l):
        for t in l:
            if isinstance(t, things.List):
                self.scanres(t.d)
            elif isinstance(t, things.Buf):
                t.d = self.pkt[self.ptr:(self.ptr+t.l)]
                self.ptr += t.l
            elif isinstance(t, things.Qword):
                t.d = self.pkt[self.ptr:(self.ptr+t.l)]
                self.ptr += t.l
            elif isinstance(t, things.Sockaddr):
                t.d = self.pkt[self.ptr:(self.ptr+6)]
                self.ptr += 6
                

