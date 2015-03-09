
import array
from hashlib import md5
from binascii import hexlify

client_id="PROD0090YUAUV{2B"
client_code="YMM8C_H7KCQ2S_KL"

def funnydigest(nonce):
    md5src=array.array('I')
    md5src.fromstring(md5(nonce+client_code).digest())
    md5arr = map(lambda x: x & 0x7fffffff, md5src)

    otherstr=nonce+client_id
    pad=len(otherstr) % 8
    if pad != 0:
        pad=8-pad
    otherstr=otherstr+('0'*pad)
    otherarr=array.array('I')
    otherarr.fromstring(otherstr)

    high=0
    low=0
    for i in range(0, len(otherarr)-1, 2):
        temp=otherarr[i]
        temp=(md5arr[0] * (((0x0e79a9c1 * temp) % 0x7fffffff) + high) + md5arr[1]) % 0x7fffffff;
        high=(md5arr[2] * ((otherarr[i+1]+temp) % 0x7fffffff) + md5arr[3]) % 0x7fffffff;
        low=(low + high + temp) & 0xffffffffffffffff;

    high += md5arr[1]
    high %= 0x7fffffff
    low += md5arr[3]
    low %= 0x7fffffff

    md5src[0] ^= high
    md5src[1] ^= low
    md5src[2] ^= high
    md5src[3] ^= low

    return hexlify(md5src.tostring())
