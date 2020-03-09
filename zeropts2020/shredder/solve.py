from pwn import *
import ctypes

LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')


found = False
seed0 = (0x5e23f5f6-i) & 0xffffffff
seed1 = (0xf17d8) & 0xffffffff
srand_seed = seed0 * seed0 + seed1 * seed1

LIBC.srand(srand_seed)

f = open('pdf.shred', 'rb').read()

output = ''
for c in f:
    byte = LIBC.rand() & 0xff
    output += chr(ord(c) ^ byte)
    

save = open('restore.pdf', 'w')
save.write(output)
save.close()




    
