
import random

def miller_rabin(n, k = 100):
    if n > 31:
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            if n % p == 0:
                return False
    d=n-1
    s=0
    while d & 1 == 0:
        d = d >> 1
        s += 1

    for i in range(k):
        a = random.randint(2,n-1)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue

        possiblyprime = False
        for j in range(s-1):
            x = (x**2)%n

            if x == 1:
                return False

            if x == n - 1:
                possiblyprime = True
                break

        if possiblyprime == False:
            return False
    return True 

def random_prime(low, high):
    r = random.randint(low, high)

    if r%2 == 0:
        r+=1

    while True:
        if miller_rabin(r) == True:
            break
        r+=2

    return r 

def nbit_prime(bits):
    return random_prime(1 << (bits - 1), (1 << bits) - 1)

def get_d(e, m):
    tm = m
    x = lasty = 0
    lastx = y = 1
    while tm != 0:
        q = e // tm
        e, tm = tm, e % tm
        x, lastx = lastx - q*x, x
        y, lasty = lasty - q*y, y

    if lastx < 0:
        return lastx + m
    else:
        return lastx

def make_rsa_keypair(bits=512):
    p = nbit_prime(bits)
    q = nbit_prime(bits)
    
    n = p*q

    e = 0x10001
    m = (p-1)*(q-1)
    d = get_d(e, m)
    
    return (e, n, d)

