import itertools
from pwn import *

# 16507344 = 2^4 3 7 73 673

a_cand = [2, 2, 2, 2, 3, 7, 73, 673]
for i in range(0, pow(2, 8)):
    a = 1
    for j in range(8):
        if (i>>j) & 1 == 1:
            a *= a_cand[j]
    print i, a

    b = 16507344 / a
    c = 21247 - a
    r = process('./mathme')

    r.sendlineafter('numbers :', str(a)+'\n'+str(b)+'\n'+str(c))
    ret = r.recvuntil('!')
    if 'correct' in ret:
        print "find:", a, b, c
        break
    r.close()



