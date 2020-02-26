from functools import reduce

def xgcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a, m):
    g, x, y = xgcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def chinese_remainder(a, n):
    # a := [a1, a2, ..., ak]
    # n := [n1, n2, ..., nk]
    total = 0
    prod = reduce(lambda x, y: x*y, n)
    for n_i, a_i in zip(n, a):
        b_i = prod // n_i
        total += a_i * b_i * modinv(b_i, n_i)
    return total % prod

a = [0x91, 0x59, 0x22, 0x67, 0xe3, 0x139]
n = [0x9b3bb7,  0x10ca38f, 0x2722ba3, 0x3e61e53, 0x316797d, 0x187c783]
print chinese_remainder(a, n)

